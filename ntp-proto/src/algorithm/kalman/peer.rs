/// This module implements a kalman filter to filter the measurements
/// provided by the peers.
///
/// The filter tracks the time difference between the local and remote
/// timescales. For ease of implementation, it actually is programmed
/// mostly as if the local timescale is absolute truth, and the remote
/// timescale is the one that is estimated. The filter state is kept at
/// a local timestamp t, and progressed in time as needed for processing
/// measurements and producing estimation outputs.
///
/// This approach is chosen so that it is possible to line up the filters
/// from multiple peers (this has no real meaning when using remote
/// timescales for that), and makes sure that we control the timescale
/// used to express the filter in.
///
/// The state is a vector (D, w) where
///  - D is the offset between the remote and local timescales
///  - w is (in seconds per second) the frequency difference.
///
/// For process noise, we assume this is fully resultant from frequency
/// drift between the local and remote timescale, and that this frequency
/// drift is assumed to be the result from a (limit of) a random walk
/// process (wiener process). Under this assumption, a timechange from t1
/// to t2 has a state propagation matrix
/// 1 (t2-t1)
/// 0    0
/// and a noise matrix given by
/// v*(t2-t1)^3/3 v*(t2-t1)^2/2
/// v*(t2-t1)^2/2   v*(t2-t1)
/// where v is a constant describing how much the frequency drifts per
/// unit of time.
///
/// This modules input consists of measurements containing:
///  - the time of the measurement t_m
///  - the measured offset d
///  - the measured transmission delay r
/// On these, we assume that
///  - there is no impact from frequency differences on r
///  - individual measurements are independent
///
/// This information on its own is not enough to feed the kalman filter.
/// For this, a further piece of information is needed: a measurement
/// related to the frequency difference. Although mathematically not
/// entirely sound, we construct the frequency measurement also using
/// the previous measurement (which we will denote with t_p and D_p).
/// It turns out this works well in practice
///
/// The observation is then the vector (D, D-D_p), and the observation
/// matrix is given by
/// 1   0
/// 0 t_m-t_p
///
/// To estimate the measurement noise, the variance s of the tranmission
/// delays r is used. Writing r as r1 - r2, where r1 is the time
/// difference on the client-to-server leg and r2 the time difference on
/// the server to client leg, we have Var(D) = Var(1/2 (r1 + r2)) = 1/4
/// Var(r1 - r2) = 1/4 Var(r). Furthermore Var(D+Dp) = Var(D) + Var(Dp)
/// = 1/2 Var(r) and Covar(D, D+Dp) = Covar(D, D) + Covar(D, Dp) = Var(D)
/// s/4 s/4
/// s/4 s/2
///
/// This setup leaves two major issues:
///  - How often do we want measurements (what is the desired polling interval)
///  - What is v
///
/// The polling interval is changed dynamically such that
/// approximately each measurement is about halved before contributing to
/// the state (see below).
///
/// The value for v is determined by observing how well the distribution
/// of measurement errors matches up with what we would statistically expect.
/// If they are often too small, v is quartered, and if they are often too
/// large, v is quadrupled (note, this corresponds with doubling/halving
/// the more intuitive standard deviation).
use tracing::{debug, error, info, trace};

use crate::{
    Measurement, NtpDuration, NtpTimestamp, PollInterval, PollIntervalLimits, SystemConfig,
};

use super::{
    config::AlgorithmConfig,
    matrix::{Matrix, Vector},
    sqr, PeerSnapshot,
};

#[derive(Debug, Default, Copy, Clone)]
struct AveragingBuffer {
    data: [f64; 8],
    next_idx: usize,
}

// Large frequency uncertainty as early time essentially gives no reasonable info on frequency.
const INITIALIZATION_FREQ_UNCERTAINTY: f64 = 100.0;

/// Approximation of 1 - the chi-squared cdf with 1 degree of freedom
/// source: https://en.wikipedia.org/wiki/Error_function
fn chi_1(chi: f64) -> f64 {
    const P: f64 = 0.3275911;
    const A1: f64 = 0.254829592;
    const A2: f64 = -0.284496736;
    const A3: f64 = 1.421413741;
    const A4: f64 = -1.453152027;
    const A5: f64 = 1.061405429;

    let x = (chi / 2.).sqrt();
    let t = 1. / (1. + P * x);
    (A1 * t + A2 * t * t + A3 * t * t * t + A4 * t * t * t * t + A5 * t * t * t * t * t)
        * (-(x * x)).exp()
}

impl AveragingBuffer {
    fn mean(&self) -> f64 {
        self.data.iter().sum::<f64>() / (self.data.len() as f64)
    }

    fn variance(&self) -> f64 {
        let mean = self.mean();
        self.data.iter().map(|v| sqr(v - mean)).sum::<f64>() / ((self.data.len() - 1) as f64)
    }

    fn update(&mut self, rtt: f64) {
        self.data[self.next_idx] = rtt;
        self.next_idx = (self.next_idx + 1) % self.data.len();
    }
}

#[derive(Debug, Clone)]
struct InitialPeerFilter {
    roundtriptime_stats: AveragingBuffer,
    init_offset: AveragingBuffer,
    last_measurement: Option<Measurement>,

    samples: i32,
}

impl InitialPeerFilter {
    fn update(&mut self, measurement: Measurement) {
        self.roundtriptime_stats
            .update(measurement.delay.to_seconds());
        self.init_offset.update(measurement.offset.to_seconds());
        self.samples += 1;
        self.last_measurement = Some(measurement);
        debug!(samples = self.samples, "Initial peer update");
    }

    fn process_offset_steering(&mut self, steer: f64) {
        for sample in self.init_offset.data.iter_mut() {
            *sample -= steer;
        }
    }
}

#[derive(Debug, Clone)]
struct PeerFilter {
    state: Vector<2>,
    uncertainty: Matrix<2, 2>,
    clock_wander: f64,

    roundtriptime_stats: AveragingBuffer,

    precision_score: i32,
    poll_score: i32,
    desired_poll_interval: PollInterval,

    last_measurement: Measurement,
    prev_was_outlier: bool,

    // Last time a packet was processed
    last_iter: NtpTimestamp,
    // Current time of the filter state.
    filter_time: NtpTimestamp,
}

impl PeerFilter {
    /// Move the filter forward to reflect the situation at a new, later timestamp
    fn progress_filtertime(&mut self, time: NtpTimestamp) {
        debug_assert!(
            !time.is_before(self.filter_time),
            "time {time:?} is before filter_time {:?}",
            self.filter_time
        );
        if time.is_before(self.filter_time) {
            return;
        }

        // Time step paremeters
        let delta_t = (time - self.filter_time).to_seconds();
        let update = Matrix::new([[1.0, delta_t], [0.0, 1.0]]);
        let process_noise = Matrix::new([
            [
                self.clock_wander * delta_t * delta_t * delta_t / 3.,
                self.clock_wander * delta_t * delta_t / 2.,
            ],
            [
                self.clock_wander * delta_t * delta_t / 2.,
                self.clock_wander * delta_t,
            ],
        ]);

        // Kalman filter update
        self.state = update * self.state;
        self.uncertainty = update * self.uncertainty * update.transpose() + process_noise;
        self.filter_time = time;

        trace!(?time, "Filter progressed");
    }

    /// Absorb knowledge from a measurement
    fn absorb_measurement(&mut self, measurement: Measurement) -> (f64, f64, f64) {
        // Measurement parameters
        let delay_variance = self.roundtriptime_stats.variance();
        let m_delta_t = (measurement.localtime - self.last_measurement.localtime).to_seconds();

        // Kalman filter update
        let measurement_vec = Vector::new_vector([measurement.offset.to_seconds()]);
        let measurement_transform = Matrix::new([[1., 0.]]);
        let measurement_noise = Matrix::new([[delay_variance / 4.]]);
        let difference = measurement_vec - measurement_transform * self.state;
        let difference_covariance =
            measurement_transform * self.uncertainty * measurement_transform.transpose()
                + measurement_noise;
        let update_strength =
            self.uncertainty * measurement_transform.transpose() * difference_covariance.inverse();
        self.state = self.state + update_strength * difference;
        self.uncertainty = ((Matrix::unit() - update_strength * measurement_transform)
            * self.uncertainty)
            .symmetrize();

        // Statistics
        let p = chi_1(difference.inner(difference_covariance.inverse() * difference));
        // Calculate an indicator of how much of the measurement was incorporated
        // into the state. 1.0 - is needed here as this should become lower as
        // measurement noise's contribution to difference uncertainty increases.
        let weight = 1.0 - measurement_noise.determinant() / difference_covariance.determinant();

        self.last_measurement = measurement;

        trace!(p, weight, "Measurement absorbed");

        (p, weight, m_delta_t)
    }

    /// Ensure we poll often enough to keep the filter well-fed with information, but
    /// not so much that each individual poll message gives us very little new information.
    fn update_desired_poll(
        &mut self,
        config: &SystemConfig,
        algo_config: &AlgorithmConfig,
        p: f64,
        weight: f64,
        measurement_period: f64,
    ) {
        // We dont want to speed up when we already want more than we get, and vice versa.
        let reference_measurement_period = self.desired_poll_interval.as_duration().to_seconds();
        if weight < algo_config.poll_low_weight
            && measurement_period / reference_measurement_period > 0.75
        {
            self.poll_score -= 1;
        } else if weight > algo_config.poll_high_weight
            && measurement_period / reference_measurement_period < 1.4
        {
            self.poll_score += 1;
        } else {
            self.poll_score -= self.poll_score.signum();
        }
        trace!(poll_score = self.poll_score, ?weight, "Poll desire update");
        if p <= algo_config.poll_jump_threshold {
            self.desired_poll_interval = config.poll_limits.min;
            self.poll_score = 0;
        } else if self.poll_score <= -algo_config.poll_hysteresis {
            self.desired_poll_interval = self.desired_poll_interval.inc(config.poll_limits);
            self.poll_score = 0;
            info!(interval = ?self.desired_poll_interval, "Increased poll interval");
        } else if self.poll_score >= algo_config.poll_hysteresis {
            self.desired_poll_interval = self.desired_poll_interval.dec(config.poll_limits);
            self.poll_score = 0;
            info!(interval = ?self.desired_poll_interval, "Decreased poll interval");
        }
    }

    // Our estimate for the clock stability might be completely wrong. The code here
    // correlates the estimation for errors to what we actually observe, so we can
    // update our estimate should it turn out to be significantly off.
    fn update_wander_estimate(&mut self, algo_config: &AlgorithmConfig, p: f64, weight: f64) {
        // Note that chi is exponentially distributed with mean 2
        // Also, we do not steer towards a smaller precision estimate when measurement noise dominates.
        if 1. - p < algo_config.precision_low_probability
            && weight > algo_config.precision_min_weight
        {
            self.precision_score -= 1;
        } else if 1. - p > algo_config.precision_high_probability {
            self.precision_score += 1;
        } else {
            self.precision_score -= self.precision_score.signum()
        }
        trace!(
            precision_score = self.precision_score,
            p,
            "Wander estimate update"
        );
        if self.precision_score <= -algo_config.precision_hysteresis {
            self.clock_wander /= 4.0;
            self.precision_score = 0;
            debug!(
                wander = self.clock_wander.sqrt(),
                "Decreased wander estimate"
            );
        } else if self.precision_score >= algo_config.precision_hysteresis {
            self.clock_wander *= 4.0;
            self.precision_score = 0;
            debug!(
                wander = self.clock_wander.sqrt(),
                "Increased wander estimate"
            );
        }
    }

    /// Update our estimates based on a new measurement.
    fn update(
        &mut self,
        config: &SystemConfig,
        algo_config: &AlgorithmConfig,
        measurement: Measurement,
    ) -> bool {
        // Always update the root_delay, root_dispersion, leap second status and stratum, as they always represent the most accurate state.
        self.last_measurement.root_delay = measurement.root_delay;
        self.last_measurement.root_dispersion = measurement.root_dispersion;
        self.last_measurement.stratum = measurement.stratum;
        self.last_measurement.leap = measurement.leap;

        if measurement.localtime.is_before(self.filter_time) {
            // Ignore the past
            return false;
        }

        // Filter out one-time outliers (based on delay!)
        if !self.prev_was_outlier
            && (measurement.delay.to_seconds() - self.roundtriptime_stats.mean())
                > algo_config.delay_outlier_threshold * self.roundtriptime_stats.variance().sqrt()
        {
            self.prev_was_outlier = true;
            self.last_iter = measurement.localtime;
            return false;
        }

        // Environment update
        self.progress_filtertime(measurement.localtime);
        self.roundtriptime_stats
            .update(measurement.delay.to_seconds());

        let (p, weight, measurement_period) = self.absorb_measurement(measurement);

        self.update_wander_estimate(algo_config, p, weight);
        self.update_desired_poll(config, algo_config, p, weight, measurement_period);

        debug!(
            "peer offset {}±{}ms, freq {}±{}ppm",
            self.state.ventry(0) * 1000.,
            (self.uncertainty.entry(0, 0)
                + sqr(self.last_measurement.root_dispersion.to_seconds()))
            .sqrt()
                * 1000.,
            self.state.ventry(1) * 1e6,
            self.uncertainty.entry(1, 1).sqrt() * 1e6
        );

        true
    }

    fn process_offset_steering(&mut self, steer: f64) {
        self.state = self.state - Vector::new_vector([steer, 0.0]);
        self.last_measurement.offset -= NtpDuration::from_seconds(steer);
        self.last_measurement.localtime += NtpDuration::from_seconds(steer);
        self.filter_time += NtpDuration::from_seconds(steer);
    }

    fn process_frequency_steering(&mut self, time: NtpTimestamp, steer: f64) {
        self.progress_filtertime(time);
        self.state = self.state - Vector::new_vector([0.0, steer]);
        self.last_measurement.offset += NtpDuration::from_seconds(
            steer * (time - self.last_measurement.localtime).to_seconds(),
        );
    }
}

#[derive(Debug, Clone)]
#[allow(clippy::large_enum_variant)]
enum PeerStateInner {
    Initial(InitialPeerFilter),
    Stable(PeerFilter),
}

#[derive(Debug, Clone)]
pub(super) struct PeerState(PeerStateInner);

impl PeerState {
    pub fn new() -> Self {
        PeerState(PeerStateInner::Initial(InitialPeerFilter {
            roundtriptime_stats: AveragingBuffer::default(),
            init_offset: AveragingBuffer::default(),
            last_measurement: None,
            samples: 0,
        }))
    }

    // Returs whether the clock may need adjusting.
    pub fn update_self_using_measurement(
        &mut self,
        config: &SystemConfig,
        algo_config: &AlgorithmConfig,
        measurement: Measurement,
    ) -> bool {
        match &mut self.0 {
            PeerStateInner::Initial(filter) => {
                filter.update(measurement);
                if filter.samples == 8 {
                    *self = PeerState(PeerStateInner::Stable(PeerFilter {
                        state: Vector::new_vector([filter.init_offset.mean(), 0.]),
                        uncertainty: Matrix::new([
                            [filter.init_offset.variance(), 0.],
                            [0., sqr(algo_config.initial_frequency_uncertainty)],
                        ]),
                        clock_wander: sqr(algo_config.initial_wander),
                        roundtriptime_stats: filter.roundtriptime_stats,
                        precision_score: 0,
                        poll_score: 0,
                        desired_poll_interval: config.initial_poll,
                        last_measurement: measurement,
                        prev_was_outlier: false,
                        last_iter: measurement.localtime,
                        filter_time: measurement.localtime,
                    }));
                    debug!("Initial peer measurements complete");
                }
                true
            }
            PeerStateInner::Stable(filter) => {
                // We check that the difference between the localtime and monotonic
                // times of the measurement is in line with what would be expected
                // from recent steering. This check needs to be done here since we
                // need to revert back to the initial state.
                let localtime_difference =
                    measurement.localtime - filter.last_measurement.localtime;
                let monotime_difference = measurement
                    .monotime
                    .abs_diff(filter.last_measurement.monotime);

                if (localtime_difference - monotime_difference).abs()
                    > algo_config.meddling_threshold
                {
                    error!("Detected clock meddling");
                    *self = PeerState(PeerStateInner::Initial(InitialPeerFilter {
                        roundtriptime_stats: AveragingBuffer::default(),
                        init_offset: AveragingBuffer::default(),
                        last_measurement: None,
                        samples: 0,
                    }));
                    false
                } else {
                    filter.update(config, algo_config, measurement)
                }
            }
        }
    }

    pub fn snapshot<Index: Copy>(&self, index: Index) -> Option<PeerSnapshot<Index>> {
        match &self.0 {
            PeerStateInner::Initial(InitialPeerFilter {
                roundtriptime_stats,
                init_offset,
                last_measurement: Some(last_measurement),
                samples,
            }) if *samples > 0 => {
                let max_roundtrip = roundtriptime_stats.data[..*samples as usize]
                    .iter()
                    .copied()
                    .fold(None, |v1, v2| {
                        if v2.is_nan() {
                            v1
                        } else if let Some(v1) = v1 {
                            Some(v2.max(v1))
                        } else {
                            Some(v2)
                        }
                    })?;
                Some(PeerSnapshot {
                    index,
                    peer_uncertainty: last_measurement.root_dispersion,
                    peer_delay: last_measurement.root_delay,
                    leap_indicator: last_measurement.leap,
                    last_update: last_measurement.localtime,
                    delay: max_roundtrip,
                    state: Vector::new_vector([
                        init_offset.data[..*samples as usize]
                            .iter()
                            .copied()
                            .sum::<f64>()
                            / (*samples as f64),
                        0.0,
                    ]),
                    uncertainty: Matrix::new([
                        [max_roundtrip, 0.0],
                        [0.0, INITIALIZATION_FREQ_UNCERTAINTY],
                    ]),
                })
            }
            PeerStateInner::Stable(filter) => Some(PeerSnapshot {
                index,
                state: filter.state,
                uncertainty: filter.uncertainty,
                delay: filter.roundtriptime_stats.mean(),
                peer_uncertainty: filter.last_measurement.root_dispersion,
                peer_delay: filter.last_measurement.root_delay,
                leap_indicator: filter.last_measurement.leap,
                last_update: filter.last_iter,
            }),
            _ => None,
        }
    }

    pub fn get_filtertime(&self) -> Option<NtpTimestamp> {
        match &self.0 {
            PeerStateInner::Initial(_) => None,
            PeerStateInner::Stable(filter) => Some(filter.filter_time),
        }
    }

    pub fn get_desired_poll(&self, limits: &PollIntervalLimits) -> PollInterval {
        match &self.0 {
            PeerStateInner::Initial(_) => limits.min,
            PeerStateInner::Stable(filter) => filter.desired_poll_interval,
        }
    }

    pub fn progress_filtertime(&mut self, time: NtpTimestamp) {
        match &mut self.0 {
            PeerStateInner::Initial(_) => {}
            PeerStateInner::Stable(filter) => filter.progress_filtertime(time),
        }
    }

    pub fn process_offset_steering(&mut self, steer: f64) {
        match &mut self.0 {
            PeerStateInner::Initial(filter) => filter.process_offset_steering(steer),
            PeerStateInner::Stable(filter) => filter.process_offset_steering(steer),
        }
    }

    pub fn process_frequency_steering(&mut self, time: NtpTimestamp, steer: f64) {
        match &mut self.0 {
            PeerStateInner::Initial(_) => {}
            PeerStateInner::Stable(filter) => filter.process_frequency_steering(time, steer),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::panic::catch_unwind;

    use crate::{Measurement, NtpInstant, NtpLeapIndicator, PollIntervalLimits};

    use super::*;

    #[test]
    fn test_meddling_detection() {
        let base = NtpTimestamp::from_fixed_int(0);
        let basei = NtpInstant::now();

        let mut peer = PeerState(PeerStateInner::Stable(PeerFilter {
            state: Vector::new_vector([20e-3, 0.]),
            uncertainty: Matrix::new([[1e-6, 0.], [0., 1e-8]]),
            clock_wander: 1e-8,
            roundtriptime_stats: AveragingBuffer {
                data: [0.0, 0.0, 0.0, 0.0, 0.875e-6, 0.875e-6, 0.875e-6, 0.875e-6],
                next_idx: 0,
            },
            precision_score: 0,
            poll_score: 0,
            desired_poll_interval: PollIntervalLimits::default().min,
            last_measurement: Measurement {
                delay: NtpDuration::from_seconds(0.0),
                offset: NtpDuration::from_seconds(20e-3),
                transmit_timestamp: Default::default(),
                receive_timestamp: Default::default(),
                localtime: base,
                monotime: basei,

                stratum: 0,
                root_delay: NtpDuration::default(),
                root_dispersion: NtpDuration::default(),
                leap: NtpLeapIndicator::NoWarning,
                precision: 0,
            },
            prev_was_outlier: false,
            last_iter: base,
            filter_time: base,
        }));
        peer.update_self_using_measurement(
            &SystemConfig::default(),
            &AlgorithmConfig::default(),
            Measurement {
                delay: NtpDuration::from_seconds(0.0),
                offset: NtpDuration::from_seconds(20e-3),
                transmit_timestamp: Default::default(),
                receive_timestamp: Default::default(),
                localtime: base + NtpDuration::from_seconds(1000.0),
                monotime: basei + std::time::Duration::from_secs(2800),

                stratum: 0,
                root_delay: NtpDuration::default(),
                root_dispersion: NtpDuration::default(),
                leap: NtpLeapIndicator::NoWarning,
                precision: 0,
            },
        );
        assert!(matches!(peer, PeerState(PeerStateInner::Initial(_))));

        let mut peer = PeerState(PeerStateInner::Stable(PeerFilter {
            state: Vector::new_vector([20e-3, 0.]),
            uncertainty: Matrix::new([[1e-6, 0.], [0., 1e-8]]),
            clock_wander: 1e-8,
            roundtriptime_stats: AveragingBuffer {
                data: [0.0, 0.0, 0.0, 0.0, 0.875e-6, 0.875e-6, 0.875e-6, 0.875e-6],
                next_idx: 0,
            },
            precision_score: 0,
            poll_score: 0,
            desired_poll_interval: PollIntervalLimits::default().min,
            last_measurement: Measurement {
                delay: NtpDuration::from_seconds(0.0),
                offset: NtpDuration::from_seconds(20e-3),
                transmit_timestamp: Default::default(),
                receive_timestamp: Default::default(),
                localtime: base,
                monotime: basei,

                stratum: 0,
                root_delay: NtpDuration::default(),
                root_dispersion: NtpDuration::default(),
                leap: NtpLeapIndicator::NoWarning,
                precision: 0,
            },
            prev_was_outlier: false,
            last_iter: base,
            filter_time: base,
        }));
        peer.process_offset_steering(-1800.0);
        peer.update_self_using_measurement(
            &SystemConfig::default(),
            &AlgorithmConfig::default(),
            Measurement {
                delay: NtpDuration::from_seconds(0.0),
                offset: NtpDuration::from_seconds(20e-3),
                transmit_timestamp: Default::default(),
                receive_timestamp: Default::default(),
                localtime: base + NtpDuration::from_seconds(1000.0),
                monotime: basei + std::time::Duration::from_secs(2800),

                stratum: 0,
                root_delay: NtpDuration::default(),
                root_dispersion: NtpDuration::default(),
                leap: NtpLeapIndicator::NoWarning,
                precision: 0,
            },
        );
        assert!(matches!(peer, PeerState(PeerStateInner::Stable(_))));

        let mut peer = PeerState(PeerStateInner::Stable(PeerFilter {
            state: Vector::new_vector([20e-3, 0.]),
            uncertainty: Matrix::new([[1e-6, 0.], [0., 1e-8]]),
            clock_wander: 1e-8,
            roundtriptime_stats: AveragingBuffer {
                data: [0.0, 0.0, 0.0, 0.0, 0.875e-6, 0.875e-6, 0.875e-6, 0.875e-6],
                next_idx: 0,
            },
            precision_score: 0,
            poll_score: 0,
            desired_poll_interval: PollIntervalLimits::default().min,
            last_measurement: Measurement {
                delay: NtpDuration::from_seconds(0.0),
                offset: NtpDuration::from_seconds(20e-3),
                transmit_timestamp: Default::default(),
                receive_timestamp: Default::default(),
                localtime: base,
                monotime: basei,

                stratum: 0,
                root_delay: NtpDuration::default(),
                root_dispersion: NtpDuration::default(),
                leap: NtpLeapIndicator::NoWarning,
                precision: 0,
            },
            prev_was_outlier: false,
            last_iter: base,
            filter_time: base,
        }));
        peer.process_offset_steering(1800.0);
        peer.update_self_using_measurement(
            &SystemConfig::default(),
            &AlgorithmConfig::default(),
            Measurement {
                delay: NtpDuration::from_seconds(0.0),
                offset: NtpDuration::from_seconds(20e-3),
                transmit_timestamp: Default::default(),
                receive_timestamp: Default::default(),
                localtime: base + NtpDuration::from_seconds(2800.0),
                monotime: basei + std::time::Duration::from_secs(1000),

                stratum: 0,
                root_delay: NtpDuration::default(),
                root_dispersion: NtpDuration::default(),
                leap: NtpLeapIndicator::NoWarning,
                precision: 0,
            },
        );
        assert!(matches!(peer, PeerState(PeerStateInner::Stable(_))));
    }

    #[test]
    fn test_offset_steering_and_measurements() {
        let base = NtpTimestamp::from_fixed_int(0);
        let basei = NtpInstant::now();
        let mut peer = PeerState(PeerStateInner::Stable(PeerFilter {
            state: Vector::new_vector([20e-3, 0.]),
            uncertainty: Matrix::new([[1e-6, 0.], [0., 1e-8]]),
            clock_wander: 1e-8,
            roundtriptime_stats: AveragingBuffer {
                data: [0.0, 0.0, 0.0, 0.0, 0.875e-6, 0.875e-6, 0.875e-6, 0.875e-6],
                next_idx: 0,
            },
            precision_score: 0,
            poll_score: 0,
            desired_poll_interval: PollIntervalLimits::default().min,
            last_measurement: Measurement {
                delay: NtpDuration::from_seconds(0.0),
                offset: NtpDuration::from_seconds(20e-3),
                transmit_timestamp: Default::default(),
                receive_timestamp: Default::default(),
                localtime: base,
                monotime: basei,

                stratum: 0,
                root_delay: NtpDuration::default(),
                root_dispersion: NtpDuration::default(),
                leap: NtpLeapIndicator::NoWarning,
                precision: 0,
            },
            prev_was_outlier: false,
            last_iter: base,
            filter_time: base,
        }));

        peer.process_offset_steering(20e-3);
        assert!(peer.snapshot(0_usize).unwrap().state.ventry(0).abs() < 1e-7);

        assert!(catch_unwind(
            move || peer.progress_filtertime(base + NtpDuration::from_seconds(10e-3))
        )
        .is_err());

        let mut peer = PeerState(PeerStateInner::Stable(PeerFilter {
            state: Vector::new_vector([20e-3, 0.]),
            uncertainty: Matrix::new([[1e-6, 0.], [0., 1e-8]]),
            clock_wander: 0.0,
            roundtriptime_stats: AveragingBuffer {
                data: [0.0, 0.0, 0.0, 0.0, 0.875e-6, 0.875e-6, 0.875e-6, 0.875e-6],
                next_idx: 0,
            },
            precision_score: 0,
            poll_score: 0,
            desired_poll_interval: PollIntervalLimits::default().min,
            last_measurement: Measurement {
                delay: NtpDuration::from_seconds(0.0),
                offset: NtpDuration::from_seconds(20e-3),
                transmit_timestamp: Default::default(),
                receive_timestamp: Default::default(),
                localtime: base,
                monotime: basei,

                stratum: 0,
                root_delay: NtpDuration::default(),
                root_dispersion: NtpDuration::default(),
                leap: NtpLeapIndicator::NoWarning,
                precision: 0,
            },
            prev_was_outlier: false,
            last_iter: base,
            filter_time: base,
        }));

        peer.process_offset_steering(20e-3);
        assert!(peer.snapshot(0_usize).unwrap().state.ventry(0).abs() < 1e-7);

        peer.update_self_using_measurement(
            &SystemConfig::default(),
            &AlgorithmConfig::default(),
            Measurement {
                delay: NtpDuration::from_seconds(0.0),
                offset: NtpDuration::from_seconds(20e-3),
                transmit_timestamp: Default::default(),
                receive_timestamp: Default::default(),
                localtime: base + NtpDuration::from_seconds(1000.0),
                monotime: basei + std::time::Duration::from_secs(1000),

                stratum: 0,
                root_delay: NtpDuration::default(),
                root_dispersion: NtpDuration::default(),
                leap: NtpLeapIndicator::NoWarning,
                precision: 0,
            },
        );

        assert!(dbg!((peer.snapshot(0_usize).unwrap().state.ventry(0) - 20e-3).abs()) < 1e-7);
        assert!((peer.snapshot(0_usize).unwrap().state.ventry(1) - 20e-6).abs() < 1e-7);

        let mut peer = PeerState(PeerStateInner::Stable(PeerFilter {
            state: Vector::new_vector([-20e-3, 0.]),
            uncertainty: Matrix::new([[1e-6, 0.], [0., 1e-8]]),
            clock_wander: 0.0,
            roundtriptime_stats: AveragingBuffer {
                data: [0.0, 0.0, 0.0, 0.0, 0.875e-6, 0.875e-6, 0.875e-6, 0.875e-6],
                next_idx: 0,
            },
            precision_score: 0,
            poll_score: 0,
            desired_poll_interval: PollIntervalLimits::default().min,
            last_measurement: Measurement {
                delay: NtpDuration::from_seconds(0.0),
                offset: NtpDuration::from_seconds(-20e-3),
                transmit_timestamp: Default::default(),
                receive_timestamp: Default::default(),
                localtime: base,
                monotime: basei,

                stratum: 0,
                root_delay: NtpDuration::default(),
                root_dispersion: NtpDuration::default(),
                leap: NtpLeapIndicator::NoWarning,
                precision: 0,
            },
            prev_was_outlier: false,
            last_iter: base,
            filter_time: base,
        }));

        peer.process_offset_steering(-20e-3);
        assert!(peer.snapshot(0_usize).unwrap().state.ventry(0).abs() < 1e-7);

        peer.progress_filtertime(base - NtpDuration::from_seconds(10e-3)); // should succeed

        peer.update_self_using_measurement(
            &SystemConfig::default(),
            &AlgorithmConfig::default(),
            Measurement {
                delay: NtpDuration::from_seconds(0.0),
                offset: NtpDuration::from_seconds(-20e-3),
                transmit_timestamp: Default::default(),
                receive_timestamp: Default::default(),
                localtime: base + NtpDuration::from_seconds(1000.0),
                monotime: basei + std::time::Duration::from_secs(1000),

                stratum: 0,
                root_delay: NtpDuration::default(),
                root_dispersion: NtpDuration::default(),
                leap: NtpLeapIndicator::NoWarning,
                precision: 0,
            },
        );

        assert!(dbg!((peer.snapshot(0_usize).unwrap().state.ventry(0) - -20e-3).abs()) < 1e-7);
        assert!((peer.snapshot(0_usize).unwrap().state.ventry(1) - -20e-6).abs() < 1e-7);
    }

    #[test]
    fn test_freq_steering() {
        let base = NtpTimestamp::from_fixed_int(0);
        let basei = NtpInstant::now();
        let mut peer = PeerFilter {
            state: Vector::new_vector([0.0, 0.]),
            uncertainty: Matrix::new([[1e-6, 0.], [0., 1e-8]]),
            clock_wander: 1e-8,
            roundtriptime_stats: AveragingBuffer {
                data: [0.0, 0.0, 0.0, 0.0, 0.875e-6, 0.875e-6, 0.875e-6, 0.875e-6],
                next_idx: 0,
            },
            precision_score: 0,
            poll_score: 0,
            desired_poll_interval: PollIntervalLimits::default().min,
            last_measurement: Measurement {
                delay: NtpDuration::from_seconds(0.0),
                offset: NtpDuration::from_seconds(0.0),
                transmit_timestamp: Default::default(),
                receive_timestamp: Default::default(),
                localtime: base,
                monotime: basei,

                stratum: 0,
                root_delay: NtpDuration::default(),
                root_dispersion: NtpDuration::default(),
                leap: NtpLeapIndicator::NoWarning,
                precision: 0,
            },
            prev_was_outlier: false,
            last_iter: base,
            filter_time: base,
        };

        peer.process_frequency_steering(base + NtpDuration::from_seconds(5.0), 200e-6);
        assert!((peer.state.ventry(1) - -200e-6).abs() < 1e-10);
        assert!(peer.state.ventry(0).abs() < 1e-8);
        assert!((peer.last_measurement.offset.to_seconds() - 1e-3).abs() < 1e-8);
        peer.process_frequency_steering(base + NtpDuration::from_seconds(10.0), -200e-6);
        assert!(peer.state.ventry(1).abs() < 1e-10);
        assert!((peer.state.ventry(0) - -1e-3).abs() < 1e-8);
        assert!((peer.last_measurement.offset.to_seconds() - -1e-3).abs() < 1e-8);

        let mut peer = PeerState(PeerStateInner::Stable(PeerFilter {
            state: Vector::new_vector([0.0, 0.]),
            uncertainty: Matrix::new([[1e-6, 0.], [0., 1e-8]]),
            clock_wander: 1e-8,
            roundtriptime_stats: AveragingBuffer {
                data: [0.0, 0.0, 0.0, 0.0, 0.875e-6, 0.875e-6, 0.875e-6, 0.875e-6],
                next_idx: 0,
            },
            precision_score: 0,
            poll_score: 0,
            desired_poll_interval: PollIntervalLimits::default().min,
            last_measurement: Measurement {
                delay: NtpDuration::from_seconds(0.0),
                offset: NtpDuration::from_seconds(0.0),
                transmit_timestamp: Default::default(),
                receive_timestamp: Default::default(),
                localtime: base,
                monotime: basei,

                stratum: 0,
                root_delay: NtpDuration::default(),
                root_dispersion: NtpDuration::default(),
                leap: NtpLeapIndicator::NoWarning,
                precision: 0,
            },
            prev_was_outlier: false,
            last_iter: base,
            filter_time: base,
        }));

        peer.process_frequency_steering(base + NtpDuration::from_seconds(5.0), 200e-6);
        assert!((peer.snapshot(0_usize).unwrap().state.ventry(1) - -200e-6).abs() < 1e-10);
        assert!(peer.snapshot(0_usize).unwrap().state.ventry(0).abs() < 1e-8);
        peer.process_frequency_steering(base + NtpDuration::from_seconds(10.0), -200e-6);
        assert!(peer.snapshot(0_usize).unwrap().state.ventry(1).abs() < 1e-10);
        assert!((peer.snapshot(0_usize).unwrap().state.ventry(0) - -1e-3).abs() < 1e-8);
    }

    #[test]
    fn test_init() {
        let base = NtpTimestamp::from_fixed_int(0);
        let basei = NtpInstant::now();
        let mut peer = PeerState::new();
        assert!(peer.snapshot(0_usize).is_none());
        peer.update_self_using_measurement(
            &SystemConfig::default(),
            &AlgorithmConfig::default(),
            Measurement {
                delay: NtpDuration::from_seconds(0.0),
                offset: NtpDuration::from_seconds(0e-3),
                transmit_timestamp: Default::default(),
                receive_timestamp: Default::default(),
                localtime: base + NtpDuration::from_seconds(1000.0),
                monotime: basei + std::time::Duration::from_secs(1000),

                stratum: 0,
                root_delay: NtpDuration::default(),
                root_dispersion: NtpDuration::default(),
                leap: NtpLeapIndicator::NoWarning,
                precision: 0,
            },
        );
        assert!(peer.snapshot(0_usize).unwrap().uncertainty.entry(1, 1) > 1.0);
        peer.update_self_using_measurement(
            &SystemConfig::default(),
            &AlgorithmConfig::default(),
            Measurement {
                delay: NtpDuration::from_seconds(0.0),
                offset: NtpDuration::from_seconds(1e-3),
                transmit_timestamp: Default::default(),
                receive_timestamp: Default::default(),
                localtime: base + NtpDuration::from_seconds(1000.0),
                monotime: basei + std::time::Duration::from_secs(1000),

                stratum: 0,
                root_delay: NtpDuration::default(),
                root_dispersion: NtpDuration::default(),
                leap: NtpLeapIndicator::NoWarning,
                precision: 0,
            },
        );
        assert!(peer.snapshot(0_usize).unwrap().uncertainty.entry(1, 1) > 1.0);
        peer.update_self_using_measurement(
            &SystemConfig::default(),
            &AlgorithmConfig::default(),
            Measurement {
                delay: NtpDuration::from_seconds(0.0),
                offset: NtpDuration::from_seconds(2e-3),
                transmit_timestamp: Default::default(),
                receive_timestamp: Default::default(),
                localtime: base + NtpDuration::from_seconds(1000.0),
                monotime: basei + std::time::Duration::from_secs(1000),

                stratum: 0,
                root_delay: NtpDuration::default(),
                root_dispersion: NtpDuration::default(),
                leap: NtpLeapIndicator::NoWarning,
                precision: 0,
            },
        );
        assert!(peer.snapshot(0_usize).unwrap().uncertainty.entry(1, 1) > 1.0);
        peer.update_self_using_measurement(
            &SystemConfig::default(),
            &AlgorithmConfig::default(),
            Measurement {
                delay: NtpDuration::from_seconds(0.0),
                offset: NtpDuration::from_seconds(3e-3),
                transmit_timestamp: Default::default(),
                receive_timestamp: Default::default(),
                localtime: base + NtpDuration::from_seconds(1000.0),
                monotime: basei + std::time::Duration::from_secs(1000),

                stratum: 0,
                root_delay: NtpDuration::default(),
                root_dispersion: NtpDuration::default(),
                leap: NtpLeapIndicator::NoWarning,
                precision: 0,
            },
        );
        assert!(peer.snapshot(0_usize).unwrap().uncertainty.entry(1, 1) > 1.0);
        peer.update_self_using_measurement(
            &SystemConfig::default(),
            &AlgorithmConfig::default(),
            Measurement {
                delay: NtpDuration::from_seconds(0.0),
                offset: NtpDuration::from_seconds(4e-3),
                transmit_timestamp: Default::default(),
                receive_timestamp: Default::default(),
                localtime: base + NtpDuration::from_seconds(1000.0),
                monotime: basei + std::time::Duration::from_secs(1000),

                stratum: 0,
                root_delay: NtpDuration::default(),
                root_dispersion: NtpDuration::default(),
                leap: NtpLeapIndicator::NoWarning,
                precision: 0,
            },
        );
        assert!(peer.snapshot(0_usize).unwrap().uncertainty.entry(1, 1) > 1.0);
        peer.update_self_using_measurement(
            &SystemConfig::default(),
            &AlgorithmConfig::default(),
            Measurement {
                delay: NtpDuration::from_seconds(0.0),
                offset: NtpDuration::from_seconds(5e-3),
                transmit_timestamp: Default::default(),
                receive_timestamp: Default::default(),
                localtime: base + NtpDuration::from_seconds(1000.0),
                monotime: basei + std::time::Duration::from_secs(1000),

                stratum: 0,
                root_delay: NtpDuration::default(),
                root_dispersion: NtpDuration::default(),
                leap: NtpLeapIndicator::NoWarning,
                precision: 0,
            },
        );
        assert!(peer.snapshot(0_usize).unwrap().uncertainty.entry(1, 1) > 1.0);
        peer.update_self_using_measurement(
            &SystemConfig::default(),
            &AlgorithmConfig::default(),
            Measurement {
                delay: NtpDuration::from_seconds(0.0),
                offset: NtpDuration::from_seconds(6e-3),
                transmit_timestamp: Default::default(),
                receive_timestamp: Default::default(),
                localtime: base + NtpDuration::from_seconds(1000.0),
                monotime: basei + std::time::Duration::from_secs(1000),

                stratum: 0,
                root_delay: NtpDuration::default(),
                root_dispersion: NtpDuration::default(),
                leap: NtpLeapIndicator::NoWarning,
                precision: 0,
            },
        );
        assert!(peer.snapshot(0_usize).unwrap().uncertainty.entry(1, 1) > 1.0);
        peer.update_self_using_measurement(
            &SystemConfig::default(),
            &AlgorithmConfig::default(),
            Measurement {
                delay: NtpDuration::from_seconds(0.0),
                offset: NtpDuration::from_seconds(7e-3),
                transmit_timestamp: Default::default(),
                receive_timestamp: Default::default(),
                localtime: base + NtpDuration::from_seconds(1000.0),
                monotime: basei + std::time::Duration::from_secs(1000),

                stratum: 0,
                root_delay: NtpDuration::default(),
                root_dispersion: NtpDuration::default(),
                leap: NtpLeapIndicator::NoWarning,
                precision: 0,
            },
        );
        assert!((peer.snapshot(0_usize).unwrap().state.ventry(0) - 3.5e-3).abs() < 1e-7);
        assert!((peer.snapshot(0_usize).unwrap().uncertainty.entry(0, 0) - 1e-6) > 0.);
    }

    #[test]
    fn test_steer_during_init() {
        let base = NtpTimestamp::from_fixed_int(0);
        let basei = NtpInstant::now();
        let mut peer = PeerState::new();
        assert!(peer.snapshot(0_usize).is_none());
        peer.update_self_using_measurement(
            &SystemConfig::default(),
            &AlgorithmConfig::default(),
            Measurement {
                delay: NtpDuration::from_seconds(0.0),
                offset: NtpDuration::from_seconds(4e-3),
                transmit_timestamp: Default::default(),
                receive_timestamp: Default::default(),
                localtime: base + NtpDuration::from_seconds(1000.0),
                monotime: basei + std::time::Duration::from_secs(1000),

                stratum: 0,
                root_delay: NtpDuration::default(),
                root_dispersion: NtpDuration::default(),
                leap: NtpLeapIndicator::NoWarning,
                precision: 0,
            },
        );
        assert!(peer.snapshot(0_usize).unwrap().uncertainty.entry(1, 1) > 1.0);
        peer.update_self_using_measurement(
            &SystemConfig::default(),
            &AlgorithmConfig::default(),
            Measurement {
                delay: NtpDuration::from_seconds(0.0),
                offset: NtpDuration::from_seconds(5e-3),
                transmit_timestamp: Default::default(),
                receive_timestamp: Default::default(),
                localtime: base + NtpDuration::from_seconds(1000.0),
                monotime: basei + std::time::Duration::from_secs(1000),

                stratum: 0,
                root_delay: NtpDuration::default(),
                root_dispersion: NtpDuration::default(),
                leap: NtpLeapIndicator::NoWarning,
                precision: 0,
            },
        );
        assert!(peer.snapshot(0_usize).unwrap().uncertainty.entry(1, 1) > 1.0);
        peer.update_self_using_measurement(
            &SystemConfig::default(),
            &AlgorithmConfig::default(),
            Measurement {
                delay: NtpDuration::from_seconds(0.0),
                offset: NtpDuration::from_seconds(6e-3),
                transmit_timestamp: Default::default(),
                receive_timestamp: Default::default(),
                localtime: base + NtpDuration::from_seconds(1000.0),
                monotime: basei + std::time::Duration::from_secs(1000),

                stratum: 0,
                root_delay: NtpDuration::default(),
                root_dispersion: NtpDuration::default(),
                leap: NtpLeapIndicator::NoWarning,
                precision: 0,
            },
        );
        assert!(peer.snapshot(0_usize).unwrap().uncertainty.entry(1, 1) > 1.0);
        peer.update_self_using_measurement(
            &SystemConfig::default(),
            &AlgorithmConfig::default(),
            Measurement {
                delay: NtpDuration::from_seconds(0.0),
                offset: NtpDuration::from_seconds(7e-3),
                transmit_timestamp: Default::default(),
                receive_timestamp: Default::default(),
                localtime: base + NtpDuration::from_seconds(1000.0),
                monotime: basei + std::time::Duration::from_secs(1000),

                stratum: 0,
                root_delay: NtpDuration::default(),
                root_dispersion: NtpDuration::default(),
                leap: NtpLeapIndicator::NoWarning,
                precision: 0,
            },
        );
        peer.process_offset_steering(4e-3);
        assert!(peer.snapshot(0_usize).unwrap().uncertainty.entry(1, 1) > 1.0);
        peer.update_self_using_measurement(
            &SystemConfig::default(),
            &AlgorithmConfig::default(),
            Measurement {
                delay: NtpDuration::from_seconds(0.0),
                offset: NtpDuration::from_seconds(4e-3),
                transmit_timestamp: Default::default(),
                receive_timestamp: Default::default(),
                localtime: base + NtpDuration::from_seconds(1000.0),
                monotime: basei + std::time::Duration::from_secs(1000),

                stratum: 0,
                root_delay: NtpDuration::default(),
                root_dispersion: NtpDuration::default(),
                leap: NtpLeapIndicator::NoWarning,
                precision: 0,
            },
        );
        assert!(peer.snapshot(0_usize).unwrap().uncertainty.entry(1, 1) > 1.0);
        peer.update_self_using_measurement(
            &SystemConfig::default(),
            &AlgorithmConfig::default(),
            Measurement {
                delay: NtpDuration::from_seconds(0.0),
                offset: NtpDuration::from_seconds(5e-3),
                transmit_timestamp: Default::default(),
                receive_timestamp: Default::default(),
                localtime: base + NtpDuration::from_seconds(1000.0),
                monotime: basei + std::time::Duration::from_secs(1000),

                stratum: 0,
                root_delay: NtpDuration::default(),
                root_dispersion: NtpDuration::default(),
                leap: NtpLeapIndicator::NoWarning,
                precision: 0,
            },
        );
        assert!(peer.snapshot(0_usize).unwrap().uncertainty.entry(1, 1) > 1.0);
        peer.update_self_using_measurement(
            &SystemConfig::default(),
            &AlgorithmConfig::default(),
            Measurement {
                delay: NtpDuration::from_seconds(0.0),
                offset: NtpDuration::from_seconds(6e-3),
                transmit_timestamp: Default::default(),
                receive_timestamp: Default::default(),
                localtime: base + NtpDuration::from_seconds(1000.0),
                monotime: basei + std::time::Duration::from_secs(1000),

                stratum: 0,
                root_delay: NtpDuration::default(),
                root_dispersion: NtpDuration::default(),
                leap: NtpLeapIndicator::NoWarning,
                precision: 0,
            },
        );
        assert!(peer.snapshot(0_usize).unwrap().uncertainty.entry(1, 1) > 1.0);
        peer.update_self_using_measurement(
            &SystemConfig::default(),
            &AlgorithmConfig::default(),
            Measurement {
                delay: NtpDuration::from_seconds(0.0),
                offset: NtpDuration::from_seconds(7e-3),
                transmit_timestamp: Default::default(),
                receive_timestamp: Default::default(),
                localtime: base + NtpDuration::from_seconds(1000.0),
                monotime: basei + std::time::Duration::from_secs(1000),

                stratum: 0,
                root_delay: NtpDuration::default(),
                root_dispersion: NtpDuration::default(),
                leap: NtpLeapIndicator::NoWarning,
                precision: 0,
            },
        );
        assert!((peer.snapshot(0_usize).unwrap().state.ventry(0) - 3.5e-3).abs() < 1e-7);
        assert!((peer.snapshot(0_usize).unwrap().uncertainty.entry(0, 0) - 1e-6) > 0.);
    }

    #[test]
    fn test_poll_duration_variation() {
        let config = SystemConfig::default();
        let algo_config = AlgorithmConfig {
            poll_hysteresis: 2,
            ..Default::default()
        };

        let base = NtpTimestamp::from_fixed_int(0);
        let basei = NtpInstant::now();
        let mut peer = PeerFilter {
            state: Vector::new_vector([0.0, 0.]),
            uncertainty: Matrix::new([[1e-6, 0.], [0., 1e-8]]),
            clock_wander: 1e-8,
            roundtriptime_stats: AveragingBuffer {
                data: [0.0, 0.0, 0.0, 0.0, 0.875e-6, 0.875e-6, 0.875e-6, 0.875e-6],
                next_idx: 0,
            },
            precision_score: 0,
            poll_score: 0,
            desired_poll_interval: PollIntervalLimits::default().min,
            last_measurement: Measurement {
                delay: NtpDuration::from_seconds(0.0),
                offset: NtpDuration::from_seconds(0.0),
                transmit_timestamp: Default::default(),
                receive_timestamp: Default::default(),
                localtime: base,
                monotime: basei,

                stratum: 0,
                root_delay: NtpDuration::default(),
                root_dispersion: NtpDuration::default(),
                leap: NtpLeapIndicator::NoWarning,
                precision: 0,
            },
            prev_was_outlier: false,
            last_iter: base,
            filter_time: base,
        };

        let baseinterval = peer.desired_poll_interval.as_duration().to_seconds();
        let pollup = peer
            .desired_poll_interval
            .inc(PollIntervalLimits::default());
        peer.update_desired_poll(&config, &algo_config, 1.0, 1.0, baseinterval * 2.);
        assert_eq!(peer.poll_score, 0);
        assert_eq!(
            peer.desired_poll_interval,
            PollIntervalLimits::default().min
        );
        peer.update_desired_poll(&config, &algo_config, 1.0, 0.0, baseinterval * 2.);
        assert_eq!(peer.poll_score, -1);
        assert_eq!(
            peer.desired_poll_interval,
            PollIntervalLimits::default().min
        );
        peer.update_desired_poll(&config, &algo_config, 1.0, 0.0, baseinterval * 2.);
        assert_eq!(peer.poll_score, 0);
        assert_eq!(peer.desired_poll_interval, pollup);
        peer.update_desired_poll(&config, &algo_config, 1.0, 1.0, baseinterval * 3.);
        assert_eq!(peer.poll_score, 0);
        assert_eq!(peer.desired_poll_interval, pollup);
        peer.update_desired_poll(&config, &algo_config, 1.0, 0.0, baseinterval);
        assert_eq!(peer.poll_score, 0);
        assert_eq!(peer.desired_poll_interval, pollup);
        peer.update_desired_poll(&config, &algo_config, 0.0, 0.0, baseinterval * 3.);
        assert_eq!(peer.poll_score, 0);
        assert_eq!(
            peer.desired_poll_interval,
            PollIntervalLimits::default().min
        );
        peer.update_desired_poll(&config, &algo_config, 1.0, 0.0, baseinterval * 2.);
        assert_eq!(peer.poll_score, -1);
        assert_eq!(
            peer.desired_poll_interval,
            PollIntervalLimits::default().min
        );
        peer.update_desired_poll(&config, &algo_config, 1.0, 0.0, baseinterval * 2.);
        assert_eq!(peer.poll_score, 0);
        assert_eq!(peer.desired_poll_interval, pollup);
        peer.update_desired_poll(&config, &algo_config, 1.0, 1.0, baseinterval);
        assert_eq!(peer.poll_score, 1);
        assert_eq!(peer.desired_poll_interval, pollup);
        peer.update_desired_poll(&config, &algo_config, 1.0, 1.0, baseinterval);
        assert_eq!(peer.poll_score, 0);
        assert_eq!(
            peer.desired_poll_interval,
            PollIntervalLimits::default().min
        );
        peer.update_desired_poll(&config, &algo_config, 1.0, 0.0, baseinterval);
        assert_eq!(peer.poll_score, -1);
        assert_eq!(
            peer.desired_poll_interval,
            PollIntervalLimits::default().min
        );
        peer.update_desired_poll(
            &config,
            &algo_config,
            1.0,
            (algo_config.poll_high_weight + algo_config.poll_low_weight) / 2.,
            baseinterval,
        );
        assert_eq!(peer.poll_score, 0);
        assert_eq!(
            peer.desired_poll_interval,
            PollIntervalLimits::default().min
        );
        peer.update_desired_poll(&config, &algo_config, 1.0, 1.0, baseinterval);
        assert_eq!(peer.poll_score, 1);
        assert_eq!(
            peer.desired_poll_interval,
            PollIntervalLimits::default().min
        );
        peer.update_desired_poll(
            &config,
            &algo_config,
            1.0,
            (algo_config.poll_high_weight + algo_config.poll_low_weight) / 2.,
            baseinterval,
        );
        assert_eq!(peer.poll_score, 0);
        assert_eq!(
            peer.desired_poll_interval,
            PollIntervalLimits::default().min
        );
    }

    #[test]
    fn test_wander_estimation() {
        let algo_config = AlgorithmConfig {
            precision_hysteresis: 2,
            ..Default::default()
        };

        let base = NtpTimestamp::from_fixed_int(0);
        let basei = NtpInstant::now();
        let mut peer = PeerFilter {
            state: Vector::new_vector([0.0, 0.]),
            uncertainty: Matrix::new([[1e-6, 0.], [0., 1e-8]]),
            clock_wander: 1e-8,
            roundtriptime_stats: AveragingBuffer {
                data: [0.0, 0.0, 0.0, 0.0, 0.875e-6, 0.875e-6, 0.875e-6, 0.875e-6],
                next_idx: 0,
            },
            precision_score: 0,
            poll_score: 0,
            desired_poll_interval: PollIntervalLimits::default().min,
            last_measurement: Measurement {
                delay: NtpDuration::from_seconds(0.0),
                offset: NtpDuration::from_seconds(0.0),
                transmit_timestamp: Default::default(),
                receive_timestamp: Default::default(),
                localtime: base,
                monotime: basei,

                stratum: 0,
                root_delay: NtpDuration::default(),
                root_dispersion: NtpDuration::default(),
                leap: NtpLeapIndicator::NoWarning,
                precision: 0,
            },
            prev_was_outlier: false,
            last_iter: base,
            filter_time: base,
        };

        peer.update_wander_estimate(&algo_config, 1.0, 0.0);
        assert_eq!(peer.precision_score, 0);
        assert!((peer.clock_wander - 1e-8).abs() < 1e-12);
        peer.update_wander_estimate(&algo_config, 1.0, 1.0);
        assert_eq!(peer.precision_score, -1);
        assert!((peer.clock_wander - 1e-8).abs() < 1e-12);
        peer.update_wander_estimate(&algo_config, 1.0, 1.0);
        assert_eq!(peer.precision_score, 0);
        assert!(dbg!((peer.clock_wander - 0.25e-8).abs()) < 1e-12);
        peer.update_wander_estimate(&algo_config, 0.0, 0.0);
        assert_eq!(peer.precision_score, 1);
        assert!(dbg!((peer.clock_wander - 0.25e-8).abs()) < 1e-12);
        peer.update_wander_estimate(&algo_config, 0.0, 1.0);
        assert_eq!(peer.precision_score, 0);
        assert!((peer.clock_wander - 1e-8).abs() < 1e-12);
        peer.update_wander_estimate(&algo_config, 0.0, 0.0);
        assert_eq!(peer.precision_score, 1);
        assert!((peer.clock_wander - 1e-8).abs() < 1e-12);
        peer.update_wander_estimate(
            &algo_config,
            (algo_config.precision_high_probability + algo_config.precision_low_probability) / 2.0,
            0.0,
        );
        assert_eq!(peer.precision_score, 0);
        assert!((peer.clock_wander - 1e-8).abs() < 1e-12);
        peer.update_wander_estimate(&algo_config, 1.0, 1.0);
        assert_eq!(peer.precision_score, -1);
        assert!((peer.clock_wander - 1e-8).abs() < 1e-12);
        peer.update_wander_estimate(
            &algo_config,
            (algo_config.precision_high_probability + algo_config.precision_low_probability) / 2.0,
            0.0,
        );
        assert_eq!(peer.precision_score, 0);
        assert!((peer.clock_wander - 1e-8).abs() < 1e-12);
    }
}

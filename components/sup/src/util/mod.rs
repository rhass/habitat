// Copyright:: Copyright (c) 2015-2016 The Habitat Maintainers
//
// The terms of the Evaluation Agreement (Habitat) between Chef Software Inc.
// and the party accessing this file ("Licensee") apply to Licensee's use of
// the Software until such time that the Software is made available under an
// open source license such as the Apache 2.0 License.

pub mod convert;
pub mod path;
pub mod sys;
pub mod signals;

use time;

/// Gives us a time to stop for in seconds.
pub fn stop_time(duration: i64) -> time::Timespec {
    let current_time = time::now_utc().to_timespec();
    let wait_duration = time::Duration::seconds(duration as i64);
    let stop_time = current_time + wait_duration;
    stop_time
}
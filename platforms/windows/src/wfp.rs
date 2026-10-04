use std::{
    ffi::OsStr,
    os::windows::ffi::OsStrExt,
    ptr,
};

unsafe extern "C" {
    fn nexus_wfp_install_exact_ipv4(
        remote_ipv4: *const u16,
        application_path: *const u16,
    ) -> u32;
    fn nexus_wfp_remove_all() -> u32;

    fn nexus_wfp_session_open(session_out: *mut *mut std::ffi::c_void) -> u32;
    fn nexus_wfp_session_install_exact_ipv4(
        session: *mut std::ffi::c_void,
        remote_ipv4: *const u16,
        application_path: *const u16,
    ) -> u32;
    fn nexus_wfp_session_clear(session: *mut std::ffi::c_void) -> u32;
    fn nexus_wfp_session_close(session: *mut std::ffi::c_void);
}

fn wide(value: &OsStr) -> Vec<u16> {
    value.encode_wide().chain(std::iter::once(0)).collect()
}

pub fn install_exact_ipv4(
    remote_ipv4: &str,
    application_path: Option<&str>,
) -> Result<(), u32> {
    let remote = wide(OsStr::new(remote_ipv4));
    let application = application_path.map(|path| wide(OsStr::new(path)));

    let result = unsafe {
        nexus_wfp_install_exact_ipv4(
            remote.as_ptr(),
            application
                .as_ref()
                .map_or(ptr::null(), |value| value.as_ptr()),
        )
    };

    if result == 0 {
        Ok(())
    } else {
        Err(result)
    }
}

pub fn remove_all() -> Result<(), u32> {
    let result = unsafe { nexus_wfp_remove_all() };
    if result == 0 {
        Ok(())
    } else {
        Err(result)
    }
}

#[cfg(test)]
mod tests {
    use super::wide;
    use std::ffi::OsStr;

    #[test]
    fn wide_strings_are_null_terminated() {
        let encoded = wide(OsStr::new("203.0.113.10"));
        assert_eq!(encoded.last(), Some(&0));
        assert_eq!(encoded.iter().filter(|value| **value == 0).count(), 1);
    }
}

pub struct WfpSession {
    handle: *mut std::ffi::c_void,
}

impl WfpSession {
    pub fn open() -> Result<Self, u32> {
        let mut handle = ptr::null_mut();
        let result = unsafe { nexus_wfp_session_open(&mut handle) };
        if result == 0 && !handle.is_null() {
            Ok(Self { handle })
        } else {
            Err(if result == 0 { u32::MAX } else { result })
        }
    }

    pub fn install_exact_ipv4(
        &mut self,
        remote_ipv4: &str,
        application_path: Option<&str>,
    ) -> Result<(), u32> {
        let remote = wide(OsStr::new(remote_ipv4));
        let application = application_path.map(|path| wide(OsStr::new(path)));

        let result = unsafe {
            nexus_wfp_session_install_exact_ipv4(
                self.handle,
                remote.as_ptr(),
                application
                    .as_ref()
                    .map_or(ptr::null(), |value| value.as_ptr()),
            )
        };

        if result == 0 {
            Ok(())
        } else {
            Err(result)
        }
    }

    pub fn clear(&mut self) -> Result<(), u32> {
        let result = unsafe { nexus_wfp_session_clear(self.handle) };
        if result == 0 {
            Ok(())
        } else {
            Err(result)
        }
    }
}

impl Drop for WfpSession {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            unsafe { nexus_wfp_session_close(self.handle) };
            self.handle = ptr::null_mut();
        }
    }
}

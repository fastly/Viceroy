use fastly::{Error, Request, Response};
use http::StatusCode;

#[fastly::main]
fn main(request: Request) -> Result<Response, Error> {
    match request.get_path() {
        "/is-shield" => {
            let Some(shield_name) = request.get_header_str("shield") else {
                return Ok(Response::from_status(StatusCode::BAD_REQUEST)
                    .with_body("No 'shield' header found"));
            };

            let Ok(shield) = Shield::new(shield_name) else {
                return Ok(Response::from_status(StatusCode::INTERNAL_SERVER_ERROR)
                    .with_body(format!("Invalid shield name '{shield_name}'")));
            };

            Ok(Response::from_status(StatusCode::OK)
                .with_body(shield.running_on().to_string()))
                
        }

        _ => Ok(Response::from_status(StatusCode::NOT_FOUND)),
    }
}

//---------------------- CUT LINE -------------------------------------------
//
// The code below this line is just copied over from pre-release versions of
// the fastly and fastly-sys crates. Once versions of those crates are released
// with shielding support, we should remove this part and replace it with the
// relevent `use`s.


use fastly::Backend;
use fastly_shared::FastlyStatus;

const MAXIMUM_BACKEND_NAME_LENGTH: usize = 1024;

/// A structure representing a shielding site within Fastly.
pub struct Shield {
    plain_target: String,
    ssl_target: String,
    is_me: bool,
}

impl Shield {
    /// Load information about the given shield.
    ///
    /// Returns an object representing the shield if it is active, or an error if
    /// the string is malformed or the shield doesn't exist.
    ///
    /// Shield names are defined [on this
    /// webpage](https://www.fastly.com/documentation/guides/concepts/shielding/#shield-locations),
    /// in the "shield code" column. For example, the string "pdx-or-us" will look
    /// up our Portland, OR, USA shield site, while "paris-fr" will look up our Paris
    /// site.
    ///
    /// If you are using a major cloud provider for your primary origin site, consider
    /// looking at the "Recommended for" column, to find the Fastly POP most closely
    /// located to the given cloud provider.
    pub fn new<S: AsRef<str>>(name: S) -> Result<Self, FastlyStatus> {
        let name_bytes = name.as_ref().as_bytes();
        let mut out_buffer_size = 1024;

        let out_buffer = loop {
            let mut out_buffer = vec![0; out_buffer_size];
            let mut used_amt = 0;

            let result = unsafe {
                fastly_shielding::shield_info(
                    name_bytes.as_ptr(),
                    name_bytes.len(),
                    out_buffer.as_mut_ptr(),
                    out_buffer_size,
                    &mut used_amt,
                )
            };

            match result {
                FastlyStatus::OK => {
                    out_buffer.resize(used_amt as usize, 0);
                    break out_buffer;
                }

                FastlyStatus::BUFLEN => {
                    out_buffer_size *= 2;
                }

                _ => return Err(result),
            }
        };

        if out_buffer.len() < 3 {
            return Err(FastlyStatus::ERROR);
        }

        let is_me = out_buffer[0] != 0;
        let mut strings = (&out_buffer[1..]).split(|c| *c == 0);
        let plain_bytes = strings.next().ok_or(FastlyStatus::ERROR)?;
        let ssl_bytes = strings.next().ok_or(FastlyStatus::ERROR)?;
        // because the buffer ends in a null, we should end up with
        // one blank string, and then the end of the iterator
        let empty = strings.next().ok_or(FastlyStatus::ERROR)?;
        if !empty.is_empty() {
            return Err(FastlyStatus::ERROR);
        }
        if strings.next().is_some() {
            return Err(FastlyStatus::ERROR);
        }

        let plain_target =
            String::from_utf8(plain_bytes.to_vec()).map_err(|_| FastlyStatus::ERROR)?;
        let ssl_target = String::from_utf8(ssl_bytes.to_vec()).map_err(|_| FastlyStatus::ERROR)?;

        Ok(Shield {
            is_me,
            plain_target,
            ssl_target,
        })
    }

    /// Returns whether we are currently operating on the given shield.
    ///
    /// Technically, this may also return true in very isolated incidents in which Fastly is
    /// routing traffic from the target shield POP to the POP that this code is running on, but in
    /// these situations the results should be approximately identical.
    ///
    /// (For example, it may be the case that you are asking to shield to 'pdx-or-us'. But, for
    /// load balancing, performance, or other reasons, Fastly is temporarily shifting shielding
    /// traffic from Portland to Seattle. In that case, this function may return true for hosts
    /// running on 'bfi-wa-us', our Seattle site, because effectively the shield has moved to that
    /// location. This should give you a slightly faster experience than the alternative, in which
    /// this function would return false, you would try to forward your traffic to the Portland
    /// site, and then that traffic would be caught and redirected back to Seattle.)
    pub fn running_on(&self) -> bool {
        self.is_me
    }

    /// Returns a Backend representing an unencrypted connetion to the POP.
    ///
    /// Generally speaking, we encourage users to use [`Shield::encrypted_backend`]
    /// instead of this function. Data sent over this backend -- the unencrypted
    /// version -- will be sent over the open internet, with no protections. In
    /// most cases, this is not what you want. However, in some cases -- such as
    /// when you want to ship large data blobs that you know are already encrypted
    /// --- using these backends can prevent a double-encryption performance
    /// penalty.
    pub fn unencrypted_backend(&self) -> Result<Backend, FastlyStatus> {
        self.backend_builder(false).finish()
    }

    /// Returns a Backend representing an ecnrypted connection to the POP.
    ///
    /// For reference, this is almost always the backend that you want to use. Only
    /// use [`Shield::unencrypted_backend`] in situations in which you are 100% sure
    /// that all the data you will send and receive over the backend is already
    /// encrypted.
    pub fn encrypted_backend(&self) -> Result<Backend, FastlyStatus> {
        self.backend_builder(true).finish()
    }

    fn backend_builder(&self, encrypt_data: bool) -> ShieldBackendBuilder {
        ShieldBackendBuilder {
            _originating_shield: self,
            chosen_backend: if encrypt_data {
                self.ssl_target.as_str()
            } else {
                self.plain_target.as_str()
            },
            cache_key: None,
        }
    }
}

struct ShieldBackendBuilder<'a> {
    _originating_shield: &'a Shield,
    chosen_backend: &'a str,
    cache_key: Option<String>,
}

impl<'a> ShieldBackendBuilder<'a> {
    /// Convert this builder into its final backend form, or return an error if
    /// something has gone wrong.
    pub fn finish(self) -> Result<Backend, FastlyStatus> {
        let name_bytes = self.chosen_backend.as_bytes();
        let name_len = name_bytes.len();
        let mut options_mask = fastly_shielding::ShieldBackendOptions::default();
        let mut options = fastly_shielding::ShieldBackendConfig::default();
        let mut backend_name_buffer = vec![0; MAXIMUM_BACKEND_NAME_LENGTH];
        let mut final_backend_name_len = 0;

        if let Some(cache_key) = self.cache_key.as_deref() {
            options_mask.insert(fastly_shielding::ShieldBackendOptions::CACHE_KEY);
            options.cache_key = cache_key.as_ptr();
            options.cache_key_len = cache_key.as_bytes().len() as u32;
        }

        let result = unsafe {
            fastly_shielding::backend_for_shield(
                name_bytes.as_ptr(),
                name_len,
                options_mask,
                &options,
                backend_name_buffer.as_mut_ptr(),
                MAXIMUM_BACKEND_NAME_LENGTH,
                &mut final_backend_name_len,
            )
        };

        if result != FastlyStatus::OK {
            return Err(result);
        }

        backend_name_buffer.resize(final_backend_name_len as usize, 0);
        let backend_name =
            String::from_utf8(backend_name_buffer).map_err(|_| FastlyStatus::ERROR)?;

        Backend::from_name(&backend_name).map_err(|_| FastlyStatus::ERROR)
    }
}

mod fastly_shielding {
    use super::*;

    bitflags::bitflags! {
        #[derive(Default)]
        #[repr(transparent)]
        pub struct ShieldBackendOptions: u32 {
            const RESERVED = 1 << 0;
            const CACHE_KEY = 1 << 1;
        }
    }

    #[repr(C)]
    pub struct ShieldBackendConfig {
        pub cache_key: *const u8,
        pub cache_key_len: u32,
    }

    impl Default for ShieldBackendConfig {
        fn default() -> Self {
            ShieldBackendConfig {
                cache_key: std::ptr::null(),
                cache_key_len: 0,
            }
        }
    }

    //   (@interface func (export "shield_info")
    //     (param $name string)
    //     (param $info_block (@witx pointer (@witx char8)))
    //     (param $info_block_max_len (@witx usize))
    //     (result $err (expected $num_bytes (error $fastly_status)))
    //   )

    #[link(wasm_import_module = "fastly_shielding")]
    extern "C" {

        /// Get information about the given shield in the Fastly network
        #[link_name = "shield_info"]
        pub fn shield_info(
            name: *const u8,
            name_len: usize,
            info_block: *mut u8,
            info_block_len: usize,
            nwritten_out: *mut u32,
        ) -> FastlyStatus;

        /// Turn a pop name into a backend that we can send requests to.
        #[link_name = "backend_for_shield"]
        pub fn backend_for_shield(
            name: *const u8,
            name_len: usize,
            options_mask: ShieldBackendOptions,
            options: *const ShieldBackendConfig,
            backend_name: *mut u8,
            backend_name_len: usize,
            nwritten_out: *mut u32,
        ) -> FastlyStatus;
    }
}

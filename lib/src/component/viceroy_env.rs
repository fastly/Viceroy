use {super::fastly::api::viceroy_env, crate::session::Session};

#[async_trait::async_trait]
impl viceroy_env::Host for Session {
    async fn fastly_key(&mut self) -> Result<String, ()> {
        self.fastly_key_read().ok_or(())
    }
}

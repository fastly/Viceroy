use {
    crate::component::bindings::fastly::compute::{erl, types},
    crate::linking::ComponentCtx,
};

use wasmtime::component::Resource;

impl erl::Host for ComponentCtx {}

impl erl::HostRateCounter for ComponentCtx {
    fn open(&mut self, name: String) -> Result<Resource<String>, erl::OpenError> {
        let res = self.wasi_table.push(name).unwrap();

        Ok(res)
    }

    fn get_name(&mut self, rc: Resource<String>) -> String {
        self.wasi_table.get(&rc).unwrap().to_owned()
    }

    fn check_rate(
        &mut self,
        rc: Resource<String>,
        entry: String,
        delta: u32,
        window: u32,
        limit: u32,
        pb: Resource<String>,
        ttl: u32,
    ) -> Result<bool, types::Error> {
        let rc = self.wasi_table.get(&rc).unwrap();
        let pb = self.wasi_table.get(&pb).unwrap();
        crate::component::erl::check_rate(
            &mut self.session,
            rc,
            entry,
            delta,
            window,
            limit,
            pb,
            ttl,
        )
    }

    fn increment(
        &mut self,
        rc: Resource<String>,
        entry: String,
        delta: u32,
    ) -> Result<(), types::Error> {
        let rc = self.wasi_table.get(&rc).unwrap();
        crate::component::erl::ratecounter_increment(&mut self.session, rc, entry, delta)
    }

    fn lookup_rate(
        &mut self,
        rc: Resource<String>,
        entry: String,
        window: u32,
    ) -> Result<u32, types::Error> {
        let rc = self.wasi_table.get(&rc).unwrap();
        crate::component::erl::ratecounter_lookup_rate(&mut self.session, rc, entry, window)
    }

    fn lookup_count(
        &mut self,
        rc: Resource<String>,
        entry: String,
        duration: u32,
    ) -> Result<u32, types::Error> {
        let rc = self.wasi_table.get(&rc).unwrap();
        crate::component::erl::ratecounter_lookup_count(&mut self.session, rc, entry, duration)
    }

    fn drop(&mut self, ratecounter: Resource<String>) -> wasmtime::Result<()> {
        self.wasi_table.delete(ratecounter)?;
        Ok(())
    }
}

impl erl::HostPenaltyBox for ComponentCtx {
    fn open(&mut self, name: String) -> Result<Resource<String>, erl::OpenError> {
        let res = self.wasi_table.push(name).unwrap();

        Ok(res)
    }

    fn get_name(&mut self, pb: Resource<String>) -> String {
        self.wasi_table.get(&pb).unwrap().to_owned()
    }

    fn add(&mut self, pb: Resource<String>, entry: String, ttl: u32) -> Result<(), types::Error> {
        let pb = self.wasi_table.get(&pb).unwrap();
        crate::component::erl::penaltybox_add(&mut self.session, pb, entry, ttl)
    }

    fn has(&mut self, pb: Resource<String>, entry: String) -> Result<bool, types::Error> {
        let pb = self.wasi_table.get(&pb).unwrap();
        crate::component::erl::penaltybox_has(&mut self.session, pb, entry)
    }

    fn drop(&mut self, penaltybox: Resource<String>) -> wasmtime::Result<()> {
        self.wasi_table.delete(penaltybox)?;
        Ok(())
    }
}

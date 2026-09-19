//! Turning the bypass on and off: the DNS server, the SNI proxy on 443 and 80, and the NRPT rule.

use std::{
    io,
    net::{SocketAddr, TcpListener, UdpSocket},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread::JoinHandle,
};

use crate::{
    dns::{self, Resolver},
    doh::Doh,
    log, nrpt,
    proxy::{self, LOOPBACK, Proxy},
};

pub struct Engine {
    stop: Arc<AtomicBool>,
    threads: Vec<JoinHandle<()>>,
    pub proxy: Arc<Proxy>,
    pub resolver: Arc<Resolver>,
    system_dns: bool,
}

fn bind_err(what: &str, e: io::Error) -> io::Error {
    io::Error::new(
        e.kind(),
        format!("{what} on {LOOPBACK} is in use or blocked ({e})"),
    )
}

impl Engine {
    /// Start everything. With `system_dns`, also add the NRPT rule so Windows sends the target
    /// names here (needs administrator rights); without it, only the servers run (for tests).
    pub fn start(system_dns: bool) -> io::Result<Self> {
        let doh = Arc::new(Doh::new()?);
        let proxy = Arc::new(Proxy::new(doh.clone(), log::line));
        let upstream = dns::system_servers(LOOPBACK);
        log::line(&format!("normal DNS servers: {upstream:?}"));
        let resolver = Arc::new(Resolver::new(upstream.clone(), doh.clone()));
        let udp = UdpSocket::bind(SocketAddr::from((LOOPBACK, 53)))
            .map_err(|e| bind_err("DNS port 53", e))?;
        let tls = TcpListener::bind(SocketAddr::from((LOOPBACK, 443)))
            .map_err(|e| bind_err("port 443", e))?;
        let http = TcpListener::bind(SocketAddr::from((LOOPBACK, 80)))
            .map_err(|e| bind_err("port 80", e))?;
        let stop = Arc::new(AtomicBool::new(false));
        let spawn = |name: &str, f: Box<dyn FnOnce() + Send>| {
            std::thread::Builder::new()
                .name(name.into())
                .stack_size(128 * 1024)
                .spawn(f)
        };
        let mut threads = Vec::new();
        {
            let (r, s) = (resolver.clone(), stop.clone());
            threads.push(spawn(
                "dns",
                Box::new(move || dns::serve(udp, LOOPBACK, r, s)),
            )?);
        }
        {
            let (p, s) = (proxy.clone(), stop.clone());
            threads.push(spawn(
                "tls",
                Box::new(move || proxy::serve(p, tls, true, s)),
            )?);
        }
        {
            let (p, s) = (proxy.clone(), stop.clone());
            threads.push(spawn(
                "http",
                Box::new(move || proxy::serve(p, http, false, s)),
            )?);
        }
        // Learn the ISP's block-page address before Windows starts asking us.
        resolver.learn();
        let mut e = Self {
            stop,
            threads,
            proxy,
            resolver,
            system_dns: false,
        };
        if system_dns {
            nrpt::install(&upstream)?;
            e.system_dns = true;
        }
        log::line("on");
        Ok(e)
    }

    pub fn stop(mut self) {
        self.shutdown();
    }

    fn shutdown(&mut self) {
        if self.system_dns {
            if let Err(e) = nrpt::remove() {
                log::line(&format!("removing the DNS rule: {e}"));
            }
            self.system_dns = false;
        }
        self.stop.store(true, Ordering::Relaxed);
        for t in self.threads.drain(..) {
            let _ = t.join();
        }
        log::line("off");
    }
}

impl Drop for Engine {
    fn drop(&mut self) {
        if !self.threads.is_empty() {
            self.shutdown();
        }
    }
}

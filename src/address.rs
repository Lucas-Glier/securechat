use std::fmt;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ModoExecucao {
    Listen,
    Connect,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PapelNoise {
    Initiator,
    Responder,
}

impl ModoExecucao {
    pub fn papel_noise(self) -> PapelNoise {
        match self {
            Self::Listen => PapelNoise::Responder,
            Self::Connect => PapelNoise::Initiator,
        }
    }
}

impl FromStr for ModoExecucao {
    type Err = ErroEndereco;

    fn from_str(valor: &str) -> Result<Self, Self::Err> {
        match valor {
            "listen" => Ok(Self::Listen),
            "connect" => Ok(Self::Connect),
            _ => Err(ErroEndereco),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ErroEndereco;

impl fmt::Display for ErroEndereco {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("endereço IP local ou porta inválidos")
    }
}

impl std::error::Error for ErroEndereco {}

pub fn parse_endereco_local(valor: &str) -> Result<SocketAddr, ErroEndereco> {
    let endereco: SocketAddr = valor.parse().map_err(|_| ErroEndereco)?;
    validar_endereco_local(endereco)?;
    Ok(endereco)
}

pub fn validar_endereco_local(endereco: SocketAddr) -> Result<(), ErroEndereco> {
    if endereco.port() == 0 || !ip_permitido(endereco.ip()) {
        return Err(ErroEndereco);
    }
    Ok(())
}

fn ip_permitido(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => ip.is_loopback() || ip.is_private(),
        IpAddr::V6(ip) => ip.is_loopback() || ip.segments()[0] & 0xfe00 == 0xfc00,
    }
}

pub fn mensagem_erro_rede(erro: &io::Error) -> &'static str {
    match erro.kind() {
        io::ErrorKind::ConnectionRefused => "conexão recusada pelo peer",
        io::ErrorKind::TimedOut => "operação de rede excedeu o tempo limite",
        io::ErrorKind::InvalidInput => "endereço ou parâmetro de rede inválido",
        io::ErrorKind::AddrInUse => "endereço ou porta já está em uso",
        io::ErrorKind::AddrNotAvailable => "endereço não está disponível nesta máquina",
        io::ErrorKind::NetworkUnreachable => "rede inacessível",
        io::ErrorKind::HostUnreachable => "host inacessível",
        _ => "falha de rede",
    }
}

pub fn erro_publico_rede(erro: io::Error) -> io::Error {
    io::Error::new(erro.kind(), mensagem_erro_rede(&erro))
}

mod noise_lab;

use std::io;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let resultado = noise_lab::executar_handshake_local()?;

    if !resultado.channel_binding_confirmado() || !resultado.payloads_vazios() {
        return Err(io::Error::other("o laboratório não satisfez suas invariantes").into());
    }

    println!("Handshake Noise XX concluído.");
    println!("Channel binding idêntico para Alice e Bob.");
    println!("Fingerprint: {}", resultado.fingerprint());

    Ok(())
}

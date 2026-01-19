use pyo3::prelude::*;
use pyo3::exceptions::PyValueError;

use opaque_ke::{
    CipherSuite,
    ClientLogin, ClientLoginFinishParameters,
    ClientRegistration, ClientRegistrationFinishParameters,
    ServerLogin, ServerLoginParameters,
    ServerRegistration, ServerSetup,
    CredentialFinalization, CredentialRequest, CredentialResponse,
    RegistrationRequest, RegistrationResponse, RegistrationUpload,
};

use rand::rngs::OsRng;
use sha2::Sha512;

/// OPAQUE cipher suite (RFC 9807 instantiation):
/// - OPRF group: Ristretto255
/// - AKE: TripleDH over Ristretto255 with Sha512
/// - KSF: Argon2 (enabled via opaque-ke "argon2" feature)
///
/// opaque-ke docs show using argon2::Argon2<'static> for Ksf. :contentReference[oaicite:2]{index=2}
struct OpaqueSuite;

impl CipherSuite for OpaqueSuite {
    type OprfCs = opaque_ke::Ristretto255;
    type KeyExchange = opaque_ke::TripleDh<opaque_ke::Ristretto255, Sha512>;
    type Ksf = argon2::Argon2<'static>;
}

fn py_err<E: std::fmt::Display>(e: E) -> PyErr {
    // Map Rust errors into Python ValueError for the pyo3 API.
    PyValueError::new_err(format!("{e}"))
}

#[pyfunction]
fn server_setup_new() -> PyResult<Vec<u8>> {
    // Generate and serialize a fresh server setup for OPAQUE.
    let mut rng = OsRng;
    let setup = ServerSetup::<OpaqueSuite>::new(&mut rng);
    Ok(setup.serialize().to_vec())
}

#[pyfunction]
fn client_registration_start(password: Vec<u8>) -> PyResult<(Vec<u8>, Vec<u8>)> {
    // Begin client registration and return state + request.
    let mut rng = OsRng;
    let res = ClientRegistration::<OpaqueSuite>::start(&mut rng, &password).map_err(py_err)?;
    Ok((res.state.serialize().to_vec(), res.message.serialize().to_vec()))
}

#[pyfunction]
fn server_registration_start(
    server_setup_bytes: Vec<u8>,
    reg_request_bytes: Vec<u8>,
    server_id: Vec<u8>,
) -> PyResult<Vec<u8>> {
    // Start server side of registration and return the response.
    let setup = ServerSetup::<OpaqueSuite>::deserialize(&server_setup_bytes).map_err(py_err)?;
    let req = RegistrationRequest::deserialize(&reg_request_bytes).map_err(py_err)?;
    let res = ServerRegistration::<OpaqueSuite>::start(&setup, req, &server_id).map_err(py_err)?;
    Ok(res.message.serialize().to_vec())
}

#[pyfunction]
fn client_registration_finish(
    client_state_bytes: Vec<u8>,
    password: Vec<u8>,
    reg_response_bytes: Vec<u8>,
) -> PyResult<(Vec<u8>, Vec<u8>)> {
    // Finish client registration and return upload + export key.
    let mut rng = OsRng;
    let state = ClientRegistration::<OpaqueSuite>::deserialize(&client_state_bytes).map_err(py_err)?;
    let resp = RegistrationResponse::deserialize(&reg_response_bytes).map_err(py_err)?;

    let finish = state
        .finish(
            &mut rng,
            &password,
            resp,
            ClientRegistrationFinishParameters::default(),
        )
        .map_err(py_err)?;

    Ok((finish.message.serialize().to_vec(), finish.export_key.to_vec()))
}

#[pyfunction]
fn server_registration_finish(reg_upload_bytes: Vec<u8>) -> PyResult<Vec<u8>> {
    // Finalize server registration and return the password file.
    let upload = RegistrationUpload::deserialize(&reg_upload_bytes).map_err(py_err)?;
    let password_file = ServerRegistration::<OpaqueSuite>::finish(upload);
    Ok(password_file.serialize().to_vec())
}

#[pyfunction]
fn client_login_start(password: Vec<u8>) -> PyResult<(Vec<u8>, Vec<u8>)> {
    // Begin client login and return state + credential request.
    let mut rng = OsRng;
    let res = ClientLogin::<OpaqueSuite>::start(&mut rng, &password).map_err(py_err)?;
    Ok((res.state.serialize().to_vec(), res.message.serialize().to_vec()))
}

#[pyfunction]
fn server_login_start(
    server_setup_bytes: Vec<u8>,
    password_file_bytes: Vec<u8>,
    credential_request_bytes: Vec<u8>,
    server_id: Vec<u8>,
) -> PyResult<(Vec<u8>, Vec<u8>)> {
    // Start server login and return state + credential response.
    let mut rng = OsRng;

    let setup = ServerSetup::<OpaqueSuite>::deserialize(&server_setup_bytes).map_err(py_err)?;
    let cred_req = CredentialRequest::deserialize(&credential_request_bytes).map_err(py_err)?;
    let password_file = ServerRegistration::<OpaqueSuite>::deserialize(&password_file_bytes).map_err(py_err)?;

    let res = ServerLogin::<OpaqueSuite>::start(
        &mut rng,
        &setup,
        Some(password_file),
        cred_req,
        &server_id,
        ServerLoginParameters::default(),
    )
    .map_err(py_err)?;

    Ok((res.state.serialize().to_vec(), res.message.serialize().to_vec()))
}

#[pyfunction]
fn client_login_finish(
    client_state_bytes: Vec<u8>,
    password: Vec<u8>,
    credential_response_bytes: Vec<u8>,
) -> PyResult<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    // Finish client login and return final message + session and export keys.
    let mut rng = OsRng;

    let state = ClientLogin::<OpaqueSuite>::deserialize(&client_state_bytes).map_err(py_err)?;
    let resp = CredentialResponse::deserialize(&credential_response_bytes).map_err(py_err)?;

    let res = state
        .finish(
            &mut rng,
            &password,
            resp,
            ClientLoginFinishParameters::default(),
        )
        .map_err(py_err)?;

    Ok((
        res.message.serialize().to_vec(), // CredentialFinalization
        res.session_key.to_vec(),         // shared session key
        res.export_key.to_vec(),          // export key
    ))
}

#[pyfunction]
fn server_login_finish(
    server_state_bytes: Vec<u8>,
    credential_finalization_bytes: Vec<u8>,
) -> PyResult<Vec<u8>> {
    // Finish server login and return the shared session key.
    let state = ServerLogin::<OpaqueSuite>::deserialize(&server_state_bytes).map_err(py_err)?;
    let fin = CredentialFinalization::deserialize(&credential_finalization_bytes).map_err(py_err)?;
    let res = state
        .finish(fin, ServerLoginParameters::default())
        .map_err(py_err)?;
    Ok(res.session_key.to_vec())
}

#[pymodule]
fn opaque_rs(py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    // Expose the OPAQUE bindings to Python.
    m.add_function(wrap_pyfunction!(server_setup_new, m)?)?;
    m.add_function(wrap_pyfunction!(client_registration_start, m)?)?;
    m.add_function(wrap_pyfunction!(server_registration_start, m)?)?;
    m.add_function(wrap_pyfunction!(client_registration_finish, m)?)?;
    m.add_function(wrap_pyfunction!(server_registration_finish, m)?)?;

    m.add_function(wrap_pyfunction!(client_login_start, m)?)?;
    m.add_function(wrap_pyfunction!(server_login_start, m)?)?;
    m.add_function(wrap_pyfunction!(client_login_finish, m)?)?;
    m.add_function(wrap_pyfunction!(server_login_finish, m)?)?;

    // silence unused warning for `py` while keeping the modern signature
    let _ = py;
    Ok(())
}

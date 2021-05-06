use serde::{Deserialize, Serialize};
use std::fs::OpenOptions;
use std::io::{self, Write};
use std::path::PathBuf;
use async_recursion::async_recursion;

#[derive(Serialize, Deserialize)]
pub struct User {
    pub name: String,
    pub token: String,
}

#[derive(Serialize, Deserialize)]
struct UserLogin {
    pub email: String,
    pub password: String,
}

impl From<PathBuf> for User {
    fn from(user_path: PathBuf) -> Self {
        let userfile = OpenOptions::new()
            .read(true)
            .write(true)
            .open(user_path)
            .expect("Problem opening user info file");
        let userinfo = serde_json::from_reader(userfile).unwrap();
        serde_json::from_value(userinfo).expect("Invalid user json file")
    }
}

/// Gets the credentials from the user
fn get_credentials() -> UserLogin
{
    let mut email: String = "".to_string();

    print!("Log in to mojang\nEmail: ");

    io::stdout().flush().unwrap();
    io::stdin().read_line(&mut email).unwrap();

    email = email.trim_end().to_string();

    let password: String = rpassword::prompt_password_stdout("Password: ").unwrap();

    UserLogin {
        email : email,
        password : password,
    }
}

#[async_recursion] // This transforms the function to return a BoxFuture
/// Handles auth async
pub async fn handle_auth() -> Option<User> {
    // Gets credentials
    let mut credentials: UserLogin = get_credentials();
    // Tries to authenticate the user
    let mut user = authenticate(credentials.email.as_str(), credentials.password.as_str()).await;
    // If couldnt get the user, it will ask again
    while user.is_none()
    {
        credentials = get_credentials();
        user = authenticate(credentials.email.as_str(), credentials.password.as_str()).await;
    }
    // Finally returns the user that we get
    Some(user.unwrap())
}

#[async_recursion] // This transforms the function to return a BoxFuture
/// Authenticate the user by using the email and password and trying to log into the user's mojang account
pub async fn authenticate(email: &str, password: &str) -> Option<User> {
    // The payload to send with the post request
    let payload = serde_json::json!(
    {
        "agent" : {
            "name": "Minecraft",
            "version" : 1
        },
        "username" : email,
        "password" : password
    });

    // Sends an async request
    let client = reqwest::Client::new();
    let response = client.post("https://authserver.mojang.com/authenticate")
    .json(&payload)
    .send()
    .await
    .expect("Couldn\'t sign in, please try again!");

    // Checks the status code of the response
    match response.error_for_status() {
        // if the response is okay (200) than save the user's name and token
        Ok(res) => {
            // Parse the response into json
            let userinfo_json: serde_json::Value = res.json::<serde_json::Value>().await.expect("Error parsing auth json");
            
            // Get the access token from response json
            let access_token = userinfo_json["accessToken"].clone();
            // Get the username from the response json
            let username = userinfo_json["selectedProfile"]["name"].clone();
            Some(User {
                name: username.as_str().expect("Error parsing json").to_string(),
                token: access_token
                    .as_str()
                    .expect("Error parsing json")
                    .to_string(),
            })
        },
        // Print any errors
        Err(err) => {
            println!("Got status {:?}", err.status().unwrap());
            handle_auth().await
        },
    }
}

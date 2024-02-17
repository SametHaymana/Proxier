use std::collections::HashMap;
use std::sync::Mutex;

use crate::socks5::libs::statics::AuthMethods;

pub struct Proxy {
    auth_methods: Vec<AuthMethods>,
    users: Mutex<HashMap<String, String>>,
}

impl Proxy {
    pub fn new(auth_methods: Vec<AuthMethods>) -> Proxy {
        Proxy {
            auth_methods,
            users: Mutex::new(HashMap::new()),
        }
    }

    // User operations
    pub fn add_user(
        &mut self,
        username: String,
        password: String,
    ) {
        self.users
            .lock()
            .unwrap()
            .insert(username, password);
    }

    pub fn remove_user(&mut self, username: String) {
        self.users.lock().unwrap().remove(&username);
    }

    pub fn get_user(
        &self,
        username: String,
    ) -> Option<String> {
        self.users.lock().unwrap().get(&username).cloned()
    }

    pub fn check_valid_auth_method(
        &self,
        auth_method: AuthMethods,
    ) -> bool {
        return self.auth_methods.contains(&auth_method);
    }
}

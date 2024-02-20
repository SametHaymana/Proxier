use std::sync::Mutex;
use std::{clone, collections::HashMap};

use serde::de::value;

use crate::socks5::libs::statics::{AuthMethods, FromToU8};

pub struct Proxy {
    avaliable_methods: HashMap<u8, String>,
    auth_methods: Mutex<HashMap<u8, String>>,
    users: Mutex<HashMap<String, String>>,
}

impl Proxy {
    pub fn new() -> Proxy {
        let mut avaliable_methods: HashMap<u8, String> =
            HashMap::new();

        // NoAuth
        avaliable_methods.insert(
            AuthMethods::NoAuth.to_u8(),
            format!("{:?}", AuthMethods::NoAuth),
        );
        avaliable_methods.insert(
            AuthMethods::UsernamePassword.to_u8(),
            format!("{:?}", AuthMethods::UsernamePassword),
        );

        Proxy {
            avaliable_methods,
            auth_methods: Mutex::new(HashMap::new()),
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

    // Auth methods operations

    pub fn list_avaliable_auth_methods(
        &self,
    ) -> Vec<(u8, String)> {
        self.avaliable_methods
            .iter()
            .map(|(&key, value)| (key, value.clone()))
            .collect()
    }

    pub fn list_auth_methods(&self) -> Vec<u8> {
        self.auth_methods
            .lock()
            .unwrap()
            .keys()
            .cloned()
            .collect()
    }

    pub fn check_valid_auth_method(
        &self,
        auth_method: AuthMethods,
    ) -> bool {
        self.auth_methods
            .lock()
            .unwrap()
            .contains_key(&auth_method.to_u8())
    }

    pub fn add_method(&mut self, method: u8) -> Vec<u8> {
        // Check is avaliable
        if !self.avaliable_methods.contains_key(&method) {
            return self.list_auth_methods();
        }

        self.auth_methods.lock().unwrap().insert(
            method,
            self.avaliable_methods
                .get(&method)
                .unwrap()
                .clone(),
        );

        self.list_auth_methods()
    }

    pub fn remove_method(
        &mut self,
        method: u8,
    ) -> Vec<u8> {
        self.auth_methods.lock().unwrap().remove(&method);

        self.list_auth_methods()
    }
}

use std::sync::Mutex;
use std::collections::{HashMap, BTreeSet};


use crate::socks5::libs::statics::{AuthMethods, FromToU8};

pub struct Proxy {

    /*
    
        Avaliable auth method for proxy server

    
    */
    avaliable_methods: HashMap<u8, String>,


    /*
    
        Accepted Auth methods of proxy server
    
    */
    auth_methods: Mutex<HashMap<u8, String>>,


    /*
    
        Proxy server user/pass information
    
    */
    users: Mutex<HashMap<String, String>>,


    /*
    
        Caching opption

    */
    // TODO
    cache: Mutex<bool>,


    /*
    
        Block list for remote connections
    
    */
    // TODO
    block_remote_list: Mutex<BTreeSet<String>>,



    /*

        Block list for client 
    
    */
    // TODO
    block_client_list: Mutex<BTreeSet<String>>,


    /*
    
        Max connection limit
    
    */
    // TODO
    max_connection: Mutex<u32>,



    /*
    
        Current connection count
    
    */
    // TODO
    current_connection: Mutex<u32>,


    /*

        Ad enable option, if this optiona enabled proxy server will block ad remote address,
        
        if this make enable we will grab ad domain list from remote server and block them

        ad list can be found in https://pgl.yoyo.org/adservers/
    
    */
    // TODO
    block_ad: Mutex<bool>,


    /*
    
        Block trackers option, if this optiona enabled proxy server will block tracker remote address,

        if this make enable we will grab tracker domain list from remote server and block them

    
    */
    // TODO
    block_tracker: Mutex<bool>,


    /*

        Block malware option, if this optiona enabled proxy server will block malware remote address,

        if this make enable we will grab malware domain list from remote server and block them

        Google Safe Browsing API, PhishTank, StopBadware, etc.
    
    */
    // TODO
    block_malware: Mutex<bool>,

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
            cache: Mutex::new(false),
            block_remote_list: Mutex::new(BTreeSet::new()),
            block_client_list: Mutex::new(BTreeSet::new()),
            max_connection: Mutex::new(0),
            current_connection: Mutex::new(0),
            block_ad: Mutex::new(false),
            block_tracker: Mutex::new(false),
            block_malware: Mutex::new(false),
        }
    }

    // User operations
    pub fn get_user(
        &self,
        username: String,
    ) -> Option<String> {
        self.users.lock().unwrap().get(&username).cloned()
    }

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



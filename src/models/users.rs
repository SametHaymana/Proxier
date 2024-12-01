use std::{
    collections::HashSet,
    hash::{Hash, Hasher},
    sync::Arc,
};

use uuid::Uuid;

pub type UserId = Uuid;

#[derive(Clone, Debug)]
pub struct User {
    pub user_id: UserId,
    pub user_name: String,
    pub password: String,
}

// Store User total used bandwith
// Limit bandwith
// User based access controll ( auth methods)

impl User {
    pub fn new(
        user_name: impl Into<String>,
        password: impl Into<String>,
    ) -> Self {
        Self {
            user_id: Uuid::new_v4(),
            user_name: user_name.into(),
            password: password.into(),
        }
    }

    pub fn find_user_by_name(
        users: &HashSet<User>,
        user_name: String,
    ) -> Option<User> {
        users
            .iter()
            .find(|u| u.user_name == user_name)
            .cloned()
    }

    pub fn check_user_avaliable(
        users: &HashSet<User>,
        user_name: String,
    ) -> bool {
        Self::find_user_by_name(users, user_name).is_some()
    }

    pub fn check_user_pass(
        users: &HashSet<User>,
        user_name: String,
        password: String,
    ) -> bool {
        users
            .iter()
            .find(|u| {
                u.user_name == user_name
                    && u.password == password
            })
            .is_some()
    }
}

impl PartialEq for User {
    fn eq(&self, other: &Self) -> bool {
        self.user_id == other.user_id
    }
}

impl Eq for User {}

impl Hash for User {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.user_id.hash(state);
    }
}

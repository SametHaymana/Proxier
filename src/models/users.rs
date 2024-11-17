use std::hash::{Hash, Hasher};

use uuid::Uuid;

pub type UserId = Uuid;

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
        user_name: String,
        password: String,
    ) -> Self {
        Self {
            user_id: Uuid::new_v4(),
            user_name,
            password,
        }
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

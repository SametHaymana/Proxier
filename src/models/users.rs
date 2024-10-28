use uuid::Uuid;

pub type UserId = Uuid;

pub struct User {
    pub user_id: UserId,
    pub user_name: String,
    pub password: String,
}

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

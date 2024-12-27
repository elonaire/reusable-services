use async_graphql::{MergedObject, EmptyMutation};

use super::files::mutation::FileMutation;

#[derive(MergedObject, Default)]
pub struct Mutation(EmptyMutation, FileMutation);

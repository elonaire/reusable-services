use std::sync::Arc;

use async_graphql::{
    extensions::{Extension, ExtensionContext, ExtensionFactory, NextPrepareRequest},
    Request, ServerResult,
};

struct GraphQLAuthMiddleware;

#[async_trait::async_trait]
impl Extension for GraphQLAuthMiddleware {
    async fn prepare_request(
        &self,
        ctx: &ExtensionContext<'_>,
        request: Request,
        next: NextPrepareRequest<'_>,
    ) -> ServerResult<Request> {
        // No need to access headers here; let resolvers handle it
        next.run(ctx, request).await
    }
}

impl ExtensionFactory for GraphQLAuthMiddleware {
    fn create(&self) -> Arc<dyn Extension> {
        Arc::new(GraphQLAuthMiddleware)
    }
}

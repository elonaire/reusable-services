use crate::utils::{custom_traits::AsSurrealClient, models::ForeignKey};
use serde::{Deserialize, Serialize};

/// Integration method to set foreign keys in the target service database
pub async fn add_foreign_key_if_not_exists<T, F>(db: &T, foreign_key: ForeignKey) -> Option<F>
where
    T: Clone + AsSurrealClient,
    F: for<'de> Deserialize<'de> + Serialize,
{
    let result = db
        .as_client()
        .query("SELECT * FROM type::table($table) WHERE $column = $value LIMIT 1")
        .bind(("column", foreign_key.column.clone()))
        .bind(("table", foreign_key.table.clone()))
        .bind(("value", foreign_key.foreign_key.clone()))
        .await;

    match result {
        Ok(mut result) => {
            let response: Option<F> = result.take(0).unwrap();
            if response.is_none() {
                let record_add_res = db
                    .as_client()
                    .query("INSERT INTO $table ($column) VALUES ($value)")
                    .bind(("table", foreign_key.table.clone()))
                    .bind(("column", foreign_key.column.clone()))
                    .bind(("value", foreign_key.foreign_key.clone()))
                    .await;

                match record_add_res {
                    Ok(mut res) => {
                        let res: Option<F> = res.take(0).unwrap();
                        res
                    }
                    Err(_) => None,
                }
            } else {
                // return true;
                response
            }
        }
        Err(_) => None,
    }
}

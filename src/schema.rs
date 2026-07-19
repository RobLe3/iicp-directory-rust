// SPDX-License-Identifier: Apache-2.0
//! Fail-closed MySQL schema bootstrap and compatibility verification.
//!
//! Historical SQLx migrations remain immutable evidence, but they are not a
//! safe bootstrap path for the shared Laravel schema. A genuinely empty
//! database receives the Laravel-derived baseline once. Every existing
//! database is verify-only; this module never repairs or migrates it.

use serde::Deserialize;
use sqlx::{FromRow, MySql, Pool};
use std::collections::BTreeMap;
use std::fmt;

const BASELINE_SQL: &str = include_str!("../schema/baseline-v1.sql");
const CONTRACT_JSON: &str = include_str!("../schema/contract-v1.json");

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SchemaStatus {
    BootstrappedEmpty,
    VerifiedExisting,
}

impl fmt::Display for SchemaStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BootstrappedEmpty => write!(f, "bootstrapped_empty"),
            Self::VerifiedExisting => write!(f, "verified_existing"),
        }
    }
}

#[derive(Debug)]
pub enum SchemaError {
    Database(sqlx::Error),
    InvalidContract(serde_json::Error),
    Incompatible(Vec<String>),
}

impl fmt::Display for SchemaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Database(error) => write!(f, "database operation failed: {error}"),
            Self::InvalidContract(error) => {
                write!(f, "embedded schema contract is invalid: {error}")
            }
            Self::Incompatible(problems) => format_incompatible_schema(f, problems),
        }
    }
}

fn format_incompatible_schema(f: &mut fmt::Formatter<'_>, problems: &[String]) -> fmt::Result {
    let summary = problems
        .iter()
        .take(12)
        .map(String::as_str)
        .collect::<Vec<_>>()
        .join("; ");
    write!(
        f,
        "schema incompatible ({} required contract differences); {summary}",
        problems.len()
    )
}

impl std::error::Error for SchemaError {}

impl From<sqlx::Error> for SchemaError {
    fn from(value: sqlx::Error) -> Self {
        Self::Database(value)
    }
}

#[derive(Debug, Deserialize)]
struct Contract {
    tables: BTreeMap<String, TableContract>,
}

#[derive(Debug, Deserialize)]
struct TableContract {
    columns: BTreeMap<String, ColumnContract>,
    indexes: BTreeMap<String, IndexContract>,
    foreign_keys: BTreeMap<String, ForeignKeyContract>,
}

#[derive(Debug, Deserialize)]
struct ColumnContract {
    column_type: String,
    nullable: bool,
    default: Option<String>,
    extra: String,
}

#[derive(Debug, Deserialize)]
struct IndexContract {
    unique: bool,
    columns: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct ForeignKeyContract {
    columns: Vec<String>,
    referenced_table: String,
    referenced_columns: Vec<String>,
}

#[derive(Debug, FromRow)]
struct ColumnRow {
    table_name: String,
    column_name: String,
    column_type: String,
    is_nullable: String,
    column_default: Option<String>,
    extra: String,
}

#[derive(Debug, FromRow)]
struct IndexRow {
    table_name: String,
    index_name: String,
    non_unique: i64,
    seq_in_index: i64,
    column_name: String,
}

#[derive(Debug, FromRow)]
struct ForeignKeyRow {
    table_name: String,
    constraint_name: String,
    ordinal_position: i64,
    column_name: String,
    referenced_table_name: String,
    referenced_column_name: String,
}

#[derive(Debug, Default)]
struct ActualTable {
    columns: BTreeMap<String, ColumnContract>,
    indexes: BTreeMap<String, IndexContract>,
    foreign_keys: BTreeMap<String, ForeignKeyContract>,
}

/// Bootstrap a genuinely empty database or verify an existing one.
///
/// An empty database has zero base tables. A database containing only a
/// migration-history table is therefore *not* empty and is rejected unless it
/// also satisfies the complete contract. This prevents accidental mutation of
/// `_sqlx_migrations` or Laravel's `migrations` history.
pub async fn ensure_schema(pool: &Pool<MySql>) -> Result<SchemaStatus, SchemaError> {
    let table_count = base_table_count(pool).await?;
    let status = bootstrap_empty_schema(pool, table_count).await?;
    verify_schema(pool).await?;
    Ok(status)
}

/// Verify a populated database without invoking the empty-database bootstrap.
///
/// Operational/read-only commands use this path so an accidentally empty
/// `DATABASE_URL` can never turn a status query into a schema mutation.
pub async fn verify_existing_schema(pool: &Pool<MySql>) -> Result<(), SchemaError> {
    if base_table_count(pool).await? == 0 {
        return Err(SchemaError::Incompatible(vec![
            "database is empty; operational commands are verify-only".to_string(),
        ]));
    }
    verify_schema(pool).await
}

async fn base_table_count(pool: &Pool<MySql>) -> Result<i64, SchemaError> {
    Ok(sqlx::query_scalar(
        "SELECT COUNT(*) FROM information_schema.tables \
         WHERE table_schema = DATABASE() AND table_type = 'BASE TABLE'",
    )
    .fetch_one(pool)
    .await?)
}

async fn bootstrap_empty_schema(
    pool: &Pool<MySql>,
    table_count: i64,
) -> Result<SchemaStatus, SchemaError> {
    if table_count == 0 {
        sqlx::raw_sql(BASELINE_SQL).execute(pool).await?;
        Ok(SchemaStatus::BootstrappedEmpty)
    } else {
        Ok(SchemaStatus::VerifiedExisting)
    }
}

async fn verify_schema(pool: &Pool<MySql>) -> Result<(), SchemaError> {
    let contract: Contract =
        serde_json::from_str(CONTRACT_JSON).map_err(SchemaError::InvalidContract)?;
    let actual = load_actual_schema(pool).await?;
    let problems = compare_contract(contract, &actual);
    if problems.is_empty() {
        Ok(())
    } else {
        Err(SchemaError::Incompatible(problems))
    }
}

async fn load_actual_schema(
    pool: &Pool<MySql>,
) -> Result<BTreeMap<String, ActualTable>, SchemaError> {
    let mut actual: BTreeMap<String, ActualTable> = BTreeMap::new();
    load_columns(pool, &mut actual).await?;
    load_indexes(pool, &mut actual).await?;
    load_foreign_keys(pool, &mut actual).await?;
    Ok(actual)
}

async fn load_columns(
    pool: &Pool<MySql>,
    actual: &mut BTreeMap<String, ActualTable>,
) -> Result<(), SchemaError> {
    let columns: Vec<ColumnRow> = sqlx::query_as(
        "SELECT CAST(TABLE_NAME AS CHAR) AS table_name, \
                CAST(COLUMN_NAME AS CHAR) AS column_name, \
                CAST(COLUMN_TYPE AS CHAR) AS column_type, \
                CAST(IS_NULLABLE AS CHAR) AS is_nullable, \
                CAST(COLUMN_DEFAULT AS CHAR) AS column_default, \
                CAST(EXTRA AS CHAR) AS extra \
         FROM information_schema.columns WHERE table_schema = DATABASE() \
         ORDER BY TABLE_NAME, ORDINAL_POSITION",
    )
    .fetch_all(pool)
    .await?;
    for row in columns {
        actual.entry(row.table_name).or_default().columns.insert(
            row.column_name,
            ColumnContract {
                column_type: normalize(&row.column_type),
                nullable: row.is_nullable == "YES",
                default: row.column_default.map(|value| normalize_default(&value)),
                extra: normalize(&row.extra),
            },
        );
    }
    Ok(())
}

async fn load_indexes(
    pool: &Pool<MySql>,
    actual: &mut BTreeMap<String, ActualTable>,
) -> Result<(), SchemaError> {
    let indexes: Vec<IndexRow> = sqlx::query_as(
        "SELECT CAST(TABLE_NAME AS CHAR) AS table_name, \
                CAST(INDEX_NAME AS CHAR) AS index_name, \
                CAST(NON_UNIQUE AS SIGNED) AS non_unique, \
                CAST(SEQ_IN_INDEX AS SIGNED) AS seq_in_index, \
                CAST(COLUMN_NAME AS CHAR) AS column_name \
         FROM information_schema.statistics WHERE table_schema = DATABASE() \
         ORDER BY TABLE_NAME, INDEX_NAME, SEQ_IN_INDEX",
    )
    .fetch_all(pool)
    .await?;
    for row in indexes {
        let _sequence_is_intentionally_ordered = row.seq_in_index;
        let index = actual
            .entry(row.table_name)
            .or_default()
            .indexes
            .entry(row.index_name)
            .or_insert_with(|| IndexContract {
                unique: row.non_unique == 0,
                columns: Vec::new(),
            });
        index.columns.push(row.column_name);
    }
    Ok(())
}

async fn load_foreign_keys(
    pool: &Pool<MySql>,
    actual: &mut BTreeMap<String, ActualTable>,
) -> Result<(), SchemaError> {
    let foreign_keys: Vec<ForeignKeyRow> = sqlx::query_as(
        "SELECT CAST(TABLE_NAME AS CHAR) AS table_name, \
                CAST(CONSTRAINT_NAME AS CHAR) AS constraint_name, \
                CAST(ORDINAL_POSITION AS SIGNED) AS ordinal_position, \
                CAST(COLUMN_NAME AS CHAR) AS column_name, \
                CAST(REFERENCED_TABLE_NAME AS CHAR) AS referenced_table_name, \
                CAST(REFERENCED_COLUMN_NAME AS CHAR) AS referenced_column_name \
         FROM information_schema.key_column_usage \
         WHERE table_schema = DATABASE() AND REFERENCED_TABLE_NAME IS NOT NULL \
         ORDER BY TABLE_NAME, CONSTRAINT_NAME, ORDINAL_POSITION",
    )
    .fetch_all(pool)
    .await?;
    for row in foreign_keys {
        let _sequence_is_intentionally_ordered = row.ordinal_position;
        let foreign_key = actual
            .entry(row.table_name)
            .or_default()
            .foreign_keys
            .entry(row.constraint_name)
            .or_insert_with(|| ForeignKeyContract {
                columns: Vec::new(),
                referenced_table: row.referenced_table_name,
                referenced_columns: Vec::new(),
            });
        foreign_key.columns.push(row.column_name);
        foreign_key
            .referenced_columns
            .push(row.referenced_column_name);
    }
    Ok(())
}

fn compare_contract(contract: Contract, actual: &BTreeMap<String, ActualTable>) -> Vec<String> {
    let mut problems = Vec::new();
    for (table_name, expected_table) in contract.tables {
        let Some(actual_table) = actual.get(&table_name) else {
            problems.push(format!("missing table {table_name}"));
            continue;
        };
        compare_table(&table_name, expected_table, actual_table, &mut problems);
    }
    problems
}

fn compare_table(
    table_name: &str,
    expected: TableContract,
    actual: &ActualTable,
    problems: &mut Vec<String>,
) {
    compare_columns(table_name, expected.columns, actual, problems);
    compare_indexes(table_name, expected.indexes, actual, problems);
    compare_foreign_keys(table_name, expected.foreign_keys, actual, problems);
}

fn compare_columns(
    table_name: &str,
    expected: BTreeMap<String, ColumnContract>,
    actual: &ActualTable,
    problems: &mut Vec<String>,
) {
    for (column_name, expected_column) in expected {
        match actual.columns.get(&column_name) {
            Some(found) => {
                compare_column(table_name, &column_name, &expected_column, found, problems)
            }
            None => problems.push(format!("missing column {table_name}.{column_name}")),
        }
    }
}

fn compare_indexes(
    table_name: &str,
    expected: BTreeMap<String, IndexContract>,
    actual: &ActualTable,
    problems: &mut Vec<String>,
) {
    for (index_name, expected_index) in expected {
        match actual.indexes.get(&index_name) {
            Some(found) if index_matches(found, &expected_index) => {}
            Some(_) => problems.push(format!("index mismatch {table_name}.{index_name}")),
            None => problems.push(format!("missing index {table_name}.{index_name}")),
        }
    }
}

fn index_matches(found: &IndexContract, expected: &IndexContract) -> bool {
    (&found.unique, &found.columns) == (&expected.unique, &expected.columns)
}

fn compare_foreign_keys(
    table_name: &str,
    expected: BTreeMap<String, ForeignKeyContract>,
    actual: &ActualTable,
    problems: &mut Vec<String>,
) {
    for (key_name, expected_key) in expected {
        match actual.foreign_keys.get(&key_name) {
            Some(found) if foreign_key_matches(found, &expected_key) => {}
            Some(_) => problems.push(format!("foreign key mismatch {table_name}.{key_name}")),
            None => problems.push(format!("missing foreign key {table_name}.{key_name}")),
        }
    }
}

fn foreign_key_matches(found: &ForeignKeyContract, expected: &ForeignKeyContract) -> bool {
    (
        &found.columns,
        &found.referenced_table,
        &found.referenced_columns,
    ) == (
        &expected.columns,
        &expected.referenced_table,
        &expected.referenced_columns,
    )
}

fn compare_column(
    table_name: &str,
    column_name: &str,
    expected: &ColumnContract,
    found: &ColumnContract,
    problems: &mut Vec<String>,
) {
    compare_column_shape(table_name, column_name, expected, found, problems);
    compare_column_storage(table_name, column_name, expected, found, problems);
}

fn compare_column_shape(
    table_name: &str,
    column_name: &str,
    expected: &ColumnContract,
    found: &ColumnContract,
    problems: &mut Vec<String>,
) {
    if normalize(&expected.column_type) != found.column_type {
        problems.push(format!("column type mismatch {table_name}.{column_name}"));
    }
    if expected.nullable != found.nullable {
        problems.push(format!(
            "column nullability mismatch {table_name}.{column_name}"
        ));
    }
}

fn compare_column_storage(
    table_name: &str,
    column_name: &str,
    expected: &ColumnContract,
    found: &ColumnContract,
    problems: &mut Vec<String>,
) {
    if expected.default.as_deref().map(normalize_default)
        != found.default.as_deref().map(normalize_default)
    {
        problems.push(format!(
            "column default mismatch {table_name}.{column_name}"
        ));
    }
    if normalize(&expected.extra) != found.extra {
        problems.push(format!("column extra mismatch {table_name}.{column_name}"));
    }
}

fn normalize(value: &str) -> String {
    value.trim().to_ascii_lowercase()
}

fn normalize_default(value: &str) -> String {
    normalize(value).replace("current_timestamp()", "current_timestamp")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_contract_is_parseable_and_has_core_tables() {
        let contract: Contract = serde_json::from_str(CONTRACT_JSON).unwrap();
        assert!(contract.tables.contains_key("nodes"));
        assert!(contract.tables.contains_key("capabilities"));
        assert!(contract.tables.contains_key("credit_transactions"));
    }

    #[test]
    fn default_normalization_accepts_mysql_timestamp_spelling() {
        assert_eq!(
            normalize_default("CURRENT_TIMESTAMP()"),
            "current_timestamp"
        );
        assert_eq!(normalize_default("current_timestamp"), "current_timestamp");
    }
}

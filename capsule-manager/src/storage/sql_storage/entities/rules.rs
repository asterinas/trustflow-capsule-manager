//! `SeaORM` Entity. Generated by sea-orm-codegen 0.12.15

use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq)]
#[sea_orm(table_name = "rules")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub rule_id: String,
    pub resource_uri: String,
    pub scope: String,
    pub grantee_party_ids: String,
    #[sea_orm(column_type = "Text")]
    pub columns: String,
    #[sea_orm(column_type = "Text", nullable)]
    pub op_constrants: Option<String>,
    #[sea_orm(column_type = "Text", nullable)]
    pub global_constrants: Option<String>,
    #[sea_orm(column_type = "Text")]
    pub signature: String,
    pub gmt_create: DateTime,
    pub gmt_modified: DateTime,
    pub gmt_delete: Option<DateTime>,
    pub is_deleted: i8,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::data_meta::Entity",
        from = "Column::ResourceUri",
        to = "super::data_meta::Column::ResourceUri",
        on_update = "NoAction",
        on_delete = "NoAction"
    )]
    DataMeta,
}

impl Related<super::data_meta::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::DataMeta.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}

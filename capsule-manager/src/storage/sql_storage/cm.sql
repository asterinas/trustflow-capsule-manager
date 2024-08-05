CREATE TABLE `data_meta` (
  `resource_uri` varchar(512) NOT NULL COMMENT '数据资源标识符',
  `owner_party_id` varchar(64) NOT NULL COMMENT '数据持有者 Id',
  `parents` varchar(1024) COMMENT '祖先 resource uris',
  `signature` text NOT NULL COMMENT '以上从字段 resource_uri 开始到 parents 直接拼接一起后进行签名',
  `gmt_create` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
  PRIMARY KEY (`resource_uri`)
)ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE `data_key` (
  `resource_uri` varchar(512) NOT NULL COMMENT '资源标识符',
  `encrypted_data_key` varchar(128) NOT NULL COMMENT '加密后的数据密钥',
  `iv` varchar(128) NOT NULL COMMENT 'initialization vector',
  `tag` varchar(128) NOT NULL COMMENT 'tag',
  `aad` varchar(512) NOT NULL COMMENT 'additional authenticated data',
  `gmt_create` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
  PRIMARY KEY (`resource_uri`)
)ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE `rules` (
  `rule_id` varchar(64) NOT NULL COMMENT '授权规则id',
  `resource_uri` varchar(512) NOT NULL COMMENT '资源标识符',
  `scope` varchar(64) NOT NULL COMMENT '授权范围',
  `grantee_party_ids` varchar(1024) NOT NULL COMMENT '被授权机构ID列表，用英文逗号分割，例如：xx1,xx2',
  `columns` text NOT NULL COMMENT '被授权的特征列，用英文逗号分割，例如：feature1,feature2',
  `op_constrants` text COMMENT '算子授权描述列表的 json 形式',
  `global_constrants` text COMMENT '全局授权描述列表的 json 形式',
  `signature` text NOT NULL COMMENT '以上从字段 rule_id 开始到 global_constrants 直接拼接一起后进行签名',
  `gmt_create` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
  `gmt_modified` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '更新时间',
  `gmt_delete` datetime DEFAULT NULL COMMENT '删除时间',
  `is_deleted` tinyint(1) NOT NULL DEFAULT '0' COMMENT '是否被删除',
  PRIMARY KEY (`rule_id`),
  FOREIGN KEY (`resource_uri`) REFERENCES data_meta(`resource_uri`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;



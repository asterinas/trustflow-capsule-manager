# Enrity 生成方式


SQL ORM 使用的是 [SeaORM](https://www.sea-ql.org/SeaORM/), Entity 可以使用 SeaORM 的工具生成，具体如下：

首先在数据库创建数据库表，然后执行：
```bash
sea-orm-cli generate entity \
    -u mysql://root@localhost:3306/capsulemanager \
    -o capsule-manager/src/storage/entities
```
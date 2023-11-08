use std::collections::HashSet;
use std::iter::Enumerate;

use super::Operator;

use serde::{Deserialize, Serialize};

const ANY_COLUMNS: &str = "*";

#[derive(Deserialize, Serialize, PartialEq, Clone)]
pub struct OpConstraint {
    op_name: Operator,

    #[serde(default)]
    constraints: Vec<String>,
}

#[derive(Deserialize, Serialize, PartialEq)]
pub struct Rule {
    pub rule_id: String,

    grantee_party_ids: Vec<String>,

    columns: Vec<String>,

    #[serde(default)]
    op_constraints: Vec<OpConstraint>,

    #[serde(default)]
    global_constraints: Vec<String>,
}

impl Rule {
    pub fn enable_any_columns(&self) -> bool {
        self.columns
            .iter()
            .map(|e| e == ANY_COLUMNS)
            .fold(false, |acc, elem| acc || elem)
    }

    pub fn contain_columns(&self, columns: &Vec<String>) -> bool {
        columns
            .iter()
            .all(|item1| self.columns.iter().any(|item2| item1 == item2))
    }

    pub fn has_grantee_party(&self, party_id: &String) -> bool {
        self.grantee_party_ids.contains(party_id)
    }

    pub fn enable_any_op(&self) -> bool {
        self.has_operator(&Operator::ANY)
    }

    pub fn has_operator(&self, op: &Operator) -> bool {
        self.op_constraints
            .iter()
            .map(|elem| &elem.op_name == op)
            .fold(false, |acc, elem| acc || elem)
    }

    // Get non-empty constraints related to the specific operator
    pub fn get_op_constraints<'a>(&'a self, op: &Operator) -> Vec<&'a String> {
        self.op_constraints
            .iter()
            .filter(|&x| &x.op_name == op)
            .map(|x| &x.constraints)
            .flatten()
            .filter(|&x| !x.trim().is_empty())
            .collect()
    }

    pub fn get_global_constraints<'a>(&'a self) -> &'a Vec<String> {
        &self.global_constraints
    }
    pub fn global_constraints_iter(&self) -> Enumerate<core::slice::Iter<String>> {
        self.global_constraints.iter().enumerate()
    }

    pub fn get_role_id<'a>(&'a self) -> &'a String {
        &self.rule_id
    }

    pub fn merge(&self, other: &Self) -> Self {
        // intersection
        let grantee_party_ids = self
            .grantee_party_ids
            .iter()
            .filter(|&elem| other.grantee_party_ids.contains(elem))
            .map(|elem| elem.to_owned())
            .collect();

        // union and duplicate global_constraints
        let mut hash_set: HashSet<String> =
            HashSet::from_iter(self.global_constraints.iter().cloned());
        hash_set.extend(other.global_constraints.iter().cloned());

        // intersection of ops, so far as, we only use `op_name``
        // TODO: merge op specific constraints, will use hash map to store
        // op_constraints
        let op_constraints = self
            .op_constraints
            .clone()
            .into_iter()
            .filter(|elem1| {
                other
                    .op_constraints
                    .iter()
                    .any(|elem2| elem1.op_name == elem2.op_name)
            })
            .collect();
        Self {
            // TODO: random rule id
            rule_id: String::from(""),
            grantee_party_ids,
            columns: vec![String::from("*")],
            op_constraints,
            global_constraints: hash_set.into_iter().collect(),
        }
    }
}

#[derive(Deserialize, Serialize, PartialEq, Default)]
pub struct Policy {
    // data identity
    data_uuid: String,

    rules: Vec<Rule>,
}

impl Policy {
    pub fn get_data_uuid<'a>(&'a self) -> &String {
        &self.data_uuid
    }

    pub fn rules_iter(&self) -> std::slice::Iter<Rule> {
        self.rules.iter()
    }

    pub fn rules_len(&self) -> usize {
        self.rules.len()
    }

    pub fn merge(&self, other: &Self) -> Self {
        let rules = self
            .rules
            .iter()
            .map(|rule_left| {
                other
                    .rules
                    .iter()
                    .map(|rule_right| rule_left.merge(rule_right))
            })
            .flatten()
            .collect();

        Self {
            // The new policy data_uuid will be set later.
            data_uuid: String::from(""),
            rules,
        }
    }
}

#[cfg(test)]
mod tests {

    use super::Policy;
    #[test]
    fn test_serialization() {
        let expect = r#"
        {
                "data_uuid":"data_uuid",
                "rules":[
                    {
                        "rule_id":"rule_id",
                        "grantee_party_ids":[
                            "FUWS2LJNIJCUOSKOEBJFGQJAKBKUETCJIMQEWRKZFUWS2LJNBJGQ"
                        ],
                        "op_constraints":[
                            {
                                "op_name":"OP_PSI"
                            }
                        ],
                        "columns":[
                            "col"
                        ]
                    }
                ]
            }

        "#;

        let policy: Policy = serde_json::from_str(expect).unwrap();

        assert_eq!(policy.rules_len(), 1);

        for rule in policy.rules_iter() {
            assert_eq!(rule.get_global_constraints().len(), 0)
        }
    }
}

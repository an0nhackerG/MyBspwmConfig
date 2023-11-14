// database schema

diesel::table! {
    agents (uuid) {
        uuid -> Text,
        os -> Text,
        platform -> Text,
        selfkey -> Text,
        peerkey -> Text,
        hostname -> Text,
        domain -> Text,
        enabled -> Bool,
    }
}

diesel::table! {
    tasks (uuid) {
        uuid -> Text,
        name -> Text,
        argv -> Text, // semicolon separated list
        deps -> Text, // semicolon separated list
        timeout -> Integer,
        pid -> Integer,
    }
}

diesel::table! {
    deps (uuid) {
        uuid -> Text,
        hash -> Blob,
        name -> Text,
        path -> Text,
    }
}

diesel::table! {
    history (id) {
        id -> Integer,
        agent_id -> Text,
        task_id -> Text,
        timestamp -> Text,
        status -> Integer,
        result -> Text,
    }
}

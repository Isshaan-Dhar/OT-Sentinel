CREATE EXTENSION IF NOT EXISTS timescaledb;

CREATE TABLE alerts (
    time TIMESTAMPTZ NOT NULL,
    trans_id INT NOT NULL,
    unit_id INT NOT NULL,
    func_code INT NOT NULL,
    mitre_id TEXT NOT NULL,
    description TEXT NOT NULL
);

SELECT create_hypertable('alerts', 'time');
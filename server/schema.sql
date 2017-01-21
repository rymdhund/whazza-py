drop table if exists checks;
create table checks (
  id integer primary key autoincrement,
  rule_key text not null,
  status integer not null,
  msg text not null,
  time timestamp not null default current_timestamp
);

drop table if exists rules;
create table rules (
  id integer primary key autoincrement,
  type text not null,
  key text not null unique,
  valid_period int not null,
  check_interval int not null,
  params text not null,
  checker text not null,
  update_id integer not null
);

drop table if exists notifications;
create table notifications (
  id integer primary key autoincrement,
  rule_key text not null unique,
  status integer not null
);

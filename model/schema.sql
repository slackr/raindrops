CREATE TABLE "rd_identities" (
	`id`	INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
	`identity`	varchar(32) NOT NULL,
	`password`	text,
	`email`	text,
	`timestamp`	datetime(6) NOT NULL,
	`realm`	varchar(64) DEFAULT NULL
);

CREATE TABLE "rd_keys" (
	`id`	INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
	`identity_id`	int(11) NOT NULL,
	`device`	varchar(32) NOT NULL,
	`pubkey`	text NOT NULL,
	`timestamp`	datetime(6) NOT NULL
);

CREATE TABLE "rd_nonce_history" (
	`id`	INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
	`nonce`	varchar(128) NOT NULL,
	`nonce_identity`	varchar(128) NOT NULL,
	`timestamp`	datetime(6) NOT NULL,
	`realm`	varchar(64) DEFAULT NULL,
	`device`	varchar(32) NOT NULL,
	`nonce_action`	varchar(32) DEFAULT NULL
);

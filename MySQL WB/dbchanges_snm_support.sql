//SNM Support 2.52b SQL Changes

ALTER TABLE `snm_support`.`licenses` 
ADD COLUMN `licenseexpirydate` DATE NULL AFTER `serial`;

CREATE TABLE `snm_support`.`web_services_categories` (
  `id` INT(11) NOT NULL AUTO_INCREMENT,
  `name` VARCHAR(255) NULL,
  PRIMARY KEY (`id`));
  
CREATE TABLE `snm_support`.`web_services` (
  `id` INT(11) NOT NULL,
  `category_id` INT(11) NULL,
  `domain_name` VARCHAR(255) NULL,
  `expiry_date` DATE NULL,
  `remarks` VARCHAR(255) NULL,
  PRIMARY KEY (`id`));
  
  ALTER TABLE `snm_support`.`web_services` 
ADD COLUMN `client_id` INT(11) NULL AFTER `expiry_date`;

ALTER TABLE `snm_support`.`web_services` 
ADD COLUMN `supplier_id` INT(11) NULL AFTER `client_id`;

ALTER TABLE `snm_support`.`web_services` 
CHANGE COLUMN `id` `id` INT(11) NOT NULL AUTO_INCREMENT ;

ALTER TABLE `snm_support`.`web_services_categories` 
ADD COLUMN `color` VARCHAR(7) NULL AFTER `name`;

ALTER TABLE `snm_support`.`web_services` 
CHANGE COLUMN `category_id` `categoryid` INT(11) NULL DEFAULT NULL ,
CHANGE COLUMN `domain_name` `domainname` VARCHAR(255) NULL DEFAULT NULL ,
CHANGE COLUMN `expiry_date` `expirydate` DATE NULL DEFAULT NULL ,
CHANGE COLUMN `client_id` `clientid` INT(11) NULL DEFAULT NULL ,
CHANGE COLUMN `supplier_id` `supplierid` INT(11) NULL DEFAULT NULL , RENAME TO  `snm_support`.`webservices` ;


ALTER TABLE `snm_support`.`web_services_categories` 
RENAME TO  `snm_support`.`webservicecategories` ;

CREATE TABLE `snm_support`.`accountnumber` (
  `id` INT(11) NOT NULL AUTO_INCREMENT,
  `accountnumber` VARCHAR(45) NOT NULL,
  `accountname` VARCHAR(45) NULL,
  PRIMARY KEY (`id`));
  
  ALTER TABLE `snm_support`.`accountnumber` 
ADD COLUMN `supplierid` INT(11) NULL AFTER `accountname`;

ALTER TABLE `snm_support`.`accountnumber` 
RENAME TO  `snm_support`.`accountnumbers` ;

ALTER TABLE `snm_support`.`webservices` 
CHANGE COLUMN `supplierid` `accountid` INT(11) NULL DEFAULT NULL ;


USE `snm_support`;
CREATE  OR REPLACE VIEW View1 AS (

  SELECT ws.id,an.accountnumber,sp.name FROM
    webservices as ws
  LEFT JOIN 
    accountnumbers as an
  ON
    ws.accountid=an.id
  LEFT JOIN
    suppliers sp
  ON 
    an.supplierid=sp.id
);;

ALTER TABLE `snm_support`.`issues` 
ADD COLUMN `startdate` VARCHAR(20) NOT NULL AFTER `description`;
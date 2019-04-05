-- MySQL Workbench Forward Engineering

SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0;
SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0;
SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='ONLY_FULL_GROUP_BY,STRICT_TRANS_TABLES,NO_ZERO_IN_DATE,NO_ZERO_DATE,ERROR_FOR_DIVISION_BY_ZERO,NO_ENGINE_SUBSTITUTION';

-- -----------------------------------------------------
-- Schema mydb
-- -----------------------------------------------------
-- -----------------------------------------------------
-- Schema dashboard
-- -----------------------------------------------------

-- -----------------------------------------------------
-- Schema dashboard
-- -----------------------------------------------------
CREATE SCHEMA IF NOT EXISTS `dashboard` DEFAULT CHARACTER SET utf8 ;
USE `dashboard` ;

-- -----------------------------------------------------
-- Table `dashboard`.`organizations`
-- -----------------------------------------------------
CREATE TABLE IF NOT EXISTS `dashboard`.`organizations` (
  `id` INT(11) NOT NULL AUTO_INCREMENT,
  `name` VARCHAR(45) NOT NULL DEFAULT '',
  `created_at` DATETIME NULL DEFAULT NULL,
  `updated_at` DATETIME NULL DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE INDEX `id_UNIQUE` (`id` ASC) VISIBLE)
ENGINE = InnoDB
AUTO_INCREMENT = 4
DEFAULT CHARACTER SET = utf8;


-- -----------------------------------------------------
-- Table `dashboard`.`mules`
-- -----------------------------------------------------
CREATE TABLE IF NOT EXISTS `dashboard`.`mules` (
  `id` INT(11) NOT NULL AUTO_INCREMENT,
  `success` TINYINT(4) NOT NULL DEFAULT '0',
  `organizations_id` INT(11) NOT NULL,
  `started_at` DATETIME NULL DEFAULT NULL,
  `finished_at` DATETIME NULL DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE INDEX `id_UNIQUE` (`id` ASC) VISIBLE,
  INDEX `fk_mules_organizations_idx` (`organizations_id` ASC) VISIBLE,
  CONSTRAINT `fk_mules_organizations`
    FOREIGN KEY (`organizations_id`)
    REFERENCES `dashboard`.`organizations` (`id`))
ENGINE = InnoDB
AUTO_INCREMENT = 428
DEFAULT CHARACTER SET = utf8;


-- -----------------------------------------------------
-- Table `dashboard`.`users`
-- -----------------------------------------------------
CREATE TABLE IF NOT EXISTS `dashboard`.`users` (
  `id` INT(11) NOT NULL AUTO_INCREMENT,
  `username` VARCHAR(45) NOT NULL DEFAULT 'NAME',
  `password` VARCHAR(127) NOT NULL DEFAULT '1234567890',
  `permission` INT(11) NOT NULL DEFAULT '1' COMMENT '1: can access dashboard only\\n2: can access custom reports\\n8: can make custom queries\\n9: can create new users and add/revoke admin status',
  `created_at` DATETIME NULL DEFAULT NULL,
  `updated_at` DATETIME NULL DEFAULT NULL,
  `max_latest` INT(11) NULL DEFAULT '12',
  PRIMARY KEY (`id`),
  UNIQUE INDEX `username_UNIQUE` (`username` ASC) VISIBLE,
  UNIQUE INDEX `id_UNIQUE` (`id` ASC) VISIBLE)
ENGINE = InnoDB
AUTO_INCREMENT = 5
DEFAULT CHARACTER SET = utf8;


SET SQL_MODE=@OLD_SQL_MODE;
SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS;
SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS;

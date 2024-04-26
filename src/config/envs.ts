/* eslint-disable prettier/prettier */
import 'dotenv/config';
import { Logger } from '@nestjs/common';
import * as joi from 'joi';

interface EnvVars {
  PORT: number;
  DATABASE_URL: string;
  DB_NAME: string;
  JWT_SECRET: string;
  NATS_SERVERS: string[];
}

const envsSchema = joi.object({
  PORT: joi.number().required().error(new Error('PORT IS REQUIRED')),
  NATS_SERVERS: joi.array().items(joi.string()).required().error(new Error('NATS_SERVERS IS REQUIRED')),
  DATABASE_URL: joi.string().required().error(new Error('DATABASE_URL IS REQUIRED')),
  DB_NAME: joi.string().required().error(new Error('DB_NAME IS REQUIRED')),
  JWT_SECRET: joi.string().required().error(new Error('JWT_SECRET IS REQUIRED')),
}).unknown(true);

const { error, value } = envsSchema.validate({
  ...process.env,
  NATS_SERVERS: process.env.NATS_SERVERS?.split(','), //para asegurarse que NATS_SERVERS se un string[]
});

if (error) {
  Logger.error(error.message);
  throw new Error(error.message);
}

const envVars: EnvVars = value;

export const envs = {
  port: envVars.PORT,
  databaseUrl: envVars.DATABASE_URL,
  dbName: envVars.DB_NAME,
  jwtSecret: envVars.JWT_SECRET,
  natsServers: envVars.NATS_SERVERS
};

import { Module } from '@nestjs/common';
import { AuthModule } from './auth/auth.module';
import { MongooseModule } from '@nestjs/mongoose';
import { envs } from './config';

@Module({
  controllers: [],
  providers: [],
  imports: [
    AuthModule,
    MongooseModule.forRoot(envs.databaseUrl, {
      dbName: envs.dbName,
    }),
  ],
})
export class AppModule {}

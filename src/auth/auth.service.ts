import { Injectable, Logger } from '@nestjs/common';
import { RpcException } from '@nestjs/microservices';
import { InjectModel } from '@nestjs/mongoose';
import { JwtService } from '@nestjs/jwt';

import { Model } from 'mongoose';
import * as bcrypt from 'bcrypt';

import { User } from './entities/user.entity';
import { RegisterUserDto } from './dto/register-user.dto';
import { LoginUserDto } from './dto/login-user.dto';
import { JwtPayload } from './interfaces/jwt-payload.interface';
import { envs } from '../config';

@Injectable()
export class AuthService {
  private readonly logger = new Logger('AuthService');

  constructor(
    @InjectModel(User.name)
    private userModel: Model<User>,
    private readonly jwtService: JwtService,
  ) {}

  async registerUser(registerUserDto: RegisterUserDto) {
    const { email, name, password } = registerUserDto;
    let user: User;

    try {
      user = await this.userModel.findOne({ email });

      if (user) {
        throw new RpcException({
          status: 400,
          message: 'User already registered',
        });
      }

      user = new this.userModel({
        name,
        email,
        password: bcrypt.hashSync(password, 10),
      });

      await user.save();

      // eslint-disable-next-line @typescript-eslint/no-unused-vars
      const { password: _, __v, ...newUser } = user.toJSON();

      return {
        user: newUser,
        token: await this.signJWT({
          _id: newUser._id,
          name: newUser.name,
          email: newUser.email,
        }),
      };
    } catch (error) {
      this.logger.error(error.message);
      throw new RpcException({
        status: 400,
        message: error.message,
      });
    }
  }

  async loginUser(loginUserDto: LoginUserDto) {
    const { email, password } = loginUserDto;
    let user: User;

    try {
      user = await this.userModel.findOne({ email });

      if (!user) {
        throw new RpcException({
          status: 400,
          message: 'User/password invalid credentials',
        });
      }

      const isPasswordValid = bcrypt.compareSync(password, user.password);

      if (!isPasswordValid) {
        throw new RpcException({
          status: 400,
          message: 'User/password invalid credentials',
        });
      }

      // eslint-disable-next-line @typescript-eslint/no-unused-vars
      const { password: _, __v, ...newUser } = user.toJSON();

      return {
        user: newUser,
        token: await this.signJWT({
          _id: newUser._id,
          name: newUser.name,
          email: newUser.email,
        }),
      };
    } catch (error) {
      this.logger.error(error.message);
      throw new RpcException({
        status: 400,
        message: error.message,
      });
    }
  }

  async verifyToken(token: string) {
    try {
      // eslint-disable-next-line @typescript-eslint/no-unused-vars
      const { sub, iat, exp, ...user } = this.jwtService.verify(token, {
        secret: envs.jwtSecret,
      });

      return {
        user: user,
        token: await this.signJWT(user),
      };
    } catch (error) {
      this.logger.error(error.message);
      throw new RpcException({
        status: 401,
        message: 'Invalid token',
      });
    }
  }

  private async signJWT(payload: JwtPayload) {
    return this.jwtService.sign(payload);
  }
}

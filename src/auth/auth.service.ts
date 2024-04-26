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

  /**
   * The function `registerUser` registers a new user by checking if the user already exists, hashing
   * the password, saving the user to the database, and returning user information along with a JWT
   * token.
   * @param {RegisterUserDto} registerUserDto - The `registerUserDto` parameter in the `registerUser`
   * function likely contains the data needed to register a new user. Based on the code snippet
   * provided, it seems that the `registerUserDto` object should have the following structure:
   * @returns The `registerUser` function returns an object with two properties: `user` and `token`. The
   * `user` property contains the newly registered user's information excluding the password and version
   * fields, while the `token` property contains a JWT token generated using the user's ID, name, and
   * email.
   */
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

  /**
   * This TypeScript function handles user login by verifying credentials and returning user data along
   * with a JWT token if successful.
   * @param {LoginUserDto} loginUserDto - The `loginUserDto` parameter in the `async loginUser` function
   * represents an object containing the user's login credentials, specifically the email and password.
   * It is of type `LoginUserDto`, which likely has the following structure:
   * @returns The `loginUser` function returns an object with two properties: `user` and `token`. The
   * `user` property contains the user object without the `password`, `__v`, and `_` properties, and the
   * `token` property contains a JWT token generated using the user's `_id`, `name`, and `email`
   * properties.
   */
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

  /**
   * The function `verifyToken` verifies a token, extracts user information, and signs a new JWT token
   * with the user information.
   * @param {string} token - The `verifyToken` function you provided is used to verify a JWT token. The
   * function extracts the user information from the token payload and then signs a new JWT token with
   * the user information.
   * @returns The `verifyToken` function is returning an object with two properties: `user` and `token`.
   * The `user` property contains the user information extracted from the token after verification,
   * excluding `sub`, `iat`, and `exp` fields. The `token` property contains a new JWT token generated by
   * calling the `signJWT` method with the user information.
   */
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

  /**
   * The function signJWT asynchronously signs a JWT using the provided payload.
   * @param {JwtPayload} payload - The `payload` parameter in the `signJWT` function likely contains the
   * data that you want to include in the JSON Web Token (JWT) that will be generated. This data could
   * include information such as user details, permissions, or any other relevant information that you
   * want to encode into the JWT.
   * @returns The `signJWT` method is returning a Promise, as it is an asynchronous function using the
   * `async` keyword. The Promise will resolve with the result of calling
   * `this.jwtService.sign(payload)`.
   */
  private async signJWT(payload: JwtPayload) {
    return this.jwtService.sign(payload);
  }
}

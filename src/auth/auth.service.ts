import { Injectable } from '@nestjs/common';
import { UsersService } from '../users/users.service';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcryptjs';

@Injectable()
export class AuthService {
  constructor(
    private usersService: UsersService,
    private jwtService: JwtService,
  ) {}

  async validateUser(email: string, password: string): Promise<any> {
    const user = await this.usersService.findOne(email);
    if (user && await bcrypt.compare(password, user.password)) {
      const { password, ...result } = user;
      return result;
    }
    return null;
  }

  async login(user: any) {
    const payload = { email: user.email, sub: user.id, role: user.role };
    return {
      access_token: this.jwtService.sign(payload),
    };
  }

  /*
  async register(email: string, password: string, role: string) {
    return this.usersService.create(email, password, role);
  }*/
    async register(email: string, password: string, role: string) {
      // Hash the password before saving it
      const hashedPassword = await bcrypt.hash(password, 10);
      
      // Pass the hashed password to the create method
      return this.usersService.create(email, hashedPassword, role);
    }
    
}

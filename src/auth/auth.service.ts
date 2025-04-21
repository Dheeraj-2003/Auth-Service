import { BadRequestException, ConflictException, Inject, Injectable, UnauthorizedException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Credentials } from '../credentials/credentials.entity';
import { Repository } from 'typeorm';
import * as bcrypt from 'bcrypt';
import { JwtService } from '@nestjs/jwt';
import { RegisterDto } from './dto/register.dto';
import { LoginDto } from './dto/login.dto';
import axios from 'axios';
import { USER_SERVICE } from 'src/common/constants';
import { ClientProxy } from '@nestjs/microservices';
import { lastValueFrom } from 'rxjs';

@Injectable()
export class AuthService {
    constructor(
        @InjectRepository(Credentials)
        private credentialsRepo: Repository<Credentials>,
        private jwtService: JwtService,
        @Inject(USER_SERVICE) private readonly userClient: ClientProxy,
    ) {}

    async register(dto: RegisterDto) {
        try {
            const user = await this.credentialsRepo.findOne({
                where: {
                    emailId: dto.email
                }
            });
            
            if(user){
                throw new ConflictException('User already exist');
            }

            const response =  await lastValueFrom(this.userClient.send({ cmd: 'create-user' },dto));
            console.log(response);
            
            const salt = await bcrypt.genSalt();
            const hashedPassword = await bcrypt.hash(dto.password, salt);
            
            const creds = this.credentialsRepo.create({
                emailId: dto.email,
                hashedPassword,
            });
            
            await this.credentialsRepo.save(creds);
            
            return { message: 'Registered successfully' };
        } catch (error) {
            console.log(error)
            throw(error)
        }
    }

    async validateUserCredentials(email:string,password: string) {
        const creds = await this.credentialsRepo.findOne({ where: { emailId: email } });

        if(!creds){
            throw new BadRequestException(`User doesn't exist, please register first`);
        }

        if (!(await bcrypt.compare(password, creds.hashedPassword))) {
            throw new UnauthorizedException('Invalid credentials');
        }
        return creds;
    }

    async login(dto: LoginDto) {
        const payload = { sub: dto.email };
        const token = this.jwtService.sign(payload);

        return {
            accessToken: token,
        };
    }
}

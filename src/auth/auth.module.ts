import { Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { TypeOrmModule } from '@nestjs/typeorm';
import { Credentials } from 'src/credentials/credentials.entity';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { JwtStrategy } from './strategies/jwt.strategy';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { LocalStrategy } from './strategies/local.strategy';

@Module({
    imports: [
    TypeOrmModule.forFeature([Credentials]),
    JwtModule.registerAsync({  
        imports: [ConfigModule],  
        inject: [ConfigService], 
        useFactory: (configService: ConfigService) => ({
          secret: configService.get<string>('JWT_SECRET'),
          signOptions: { expiresIn: configService.get<string>('JWT_EXPIRES_IN') || '1h' },
        }),
      }),
      ConfigModule.forRoot(),
    ],
    controllers: [AuthController],
  providers: [AuthService, JwtStrategy,LocalStrategy],
})
export class AuthModule {}

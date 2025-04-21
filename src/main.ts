import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { ConfigService } from '@nestjs/config';
import { AllExceptionFilter } from './common/filters/exception.filter';
import { ResponseInterceptor } from './common/interceptors/response.interceptor';
import { MicroserviceOptions, Transport } from '@nestjs/microservices';

async function bootstrap() {
  const app = await NestFactory.createMicroservice<MicroserviceOptions>(AppModule,{
    transport: Transport.TCP,
    options: {
      host: process.env.HOST ?? 'localhost',
      port: Number(process.env.PORT) ?? 3001,
    }
  });

  //config
  const configService = app.get(ConfigService);

  await app.listen();
  console.log(`App is running on PORT:${process.env.PORT}`);
}
bootstrap();

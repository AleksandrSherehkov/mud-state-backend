import { MiddlewareConsumer, Module, NestModule } from '@nestjs/common';
import { requestContextMiddleware } from './request-context.middleware';

@Module({})
export class RequestContextModule implements NestModule {
  configure(consumer: MiddlewareConsumer) {
    consumer.apply(requestContextMiddleware).forRoutes('*');
  }
}

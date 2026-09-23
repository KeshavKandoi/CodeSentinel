import { Body, Controller, Delete, Get, Param, Post, Query, UseGuards, UseInterceptors } from '@nestjs/common';

class JwtGuard {}
class RolesGuard {}
class FileInterceptor {}

@Controller('api')
@UseGuards(JwtGuard)
export class AppController {
  @Get('health')
  health() {
    return { ok: true };
  }

  @Get('users/:id')
  getUser(@Param('id') id: string, @Query('expand') expand: string) {
    return { id, expand };
  }

  @Post('users')
  @UseGuards(RolesGuard)
  createUser(@Body('email') email: string) {
    return { email };
  }

  @Post('upload')
  @UseInterceptors(FileInterceptor)
  upload(@Body() body: unknown) {
    return body;
  }

  @Delete(dynamicPath)
  remove(@Param('id') id: string) {
    return { id };
  }
}

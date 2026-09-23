import { Controller, Get } from '@nestjs/common';

@Controller('broken')
export class BrokenController {
  @Get('oops')

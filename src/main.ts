import { NestFactory } from '@nestjs/core';
import { Module, Injectable, Controller, Get, Post, Put, Delete, Body, Param, UseGuards, Request, BadRequestException, NotFoundException, UnauthorizedException, Query } from '@nestjs/common';
import { MongooseModule, InjectModel } from '@nestjs/mongoose';
import { Document, Model, Schema } from 'mongoose';
import { JwtModule, JwtService } from '@nestjs/jwt';
import { ConfigModule } from '@nestjs/config';
import * as bcrypt from 'bcryptjs';
import * as jwt from 'jsonwebtoken';
import * as speakeasy from 'speakeasy';
import { ApiBearerAuth, DocumentBuilder, SwaggerModule, ApiTags } from '@nestjs/swagger';
import { IsEmail, MinLength, IsString, IsNumber, IsEnum } from 'class-validator';

// ========== Helper: Environment variable safety ==========

function getEnv(key: string): string {
  const value = process.env[key];
  if (value == null) {
    throw new Error(`Missing environment variable: ${key}`);
  }
  return value;
}

// ========== DTOs ==========

class RegisterDto {
  @IsEmail()
  email: string;

  @IsString()
  @MinLength(6)
  password: string;

  @IsString()
  name: string;
}

class LoginDto {
  @IsEmail()
  email: string;

  @IsString()
  password: string;
}

class TwoFADto {
  @IsString()
  token: string;
}

class ProductDto {
  @IsString()
  name: string;

  @IsString()
  description: string;

  @IsNumber()
  price: number;

  @IsString()
  category: string;

  @IsString()
  brand?: string;
}

class CartItemDto {
  @IsString()
  productId: string;

  @IsNumber()
  quantity: number;
}

class AddressDto {
  @IsString()
  street: string;

  @IsString()
  city: string;

  @IsString()
  country: string;
}

class UpdateCartItemQuantityDto {
  @IsNumber()
  quantity: number;
}

class CreatePaymentDto {
  @IsEnum(['payme', 'click', 'uzum', 'cash'])
  method: 'payme' | 'click' | 'uzum' | 'cash';
}

class AdminLoginDto {
  @IsEmail()
  email: string;

  @IsString()
  password: string;
}

// ========== Schemas ==========

interface User extends Document {
  email: string;
  password: string;
  name: string;
  twoFactorSecret?: string;
  twoFactorEnabled: boolean;
  role: 'user' | 'admin';
  refreshToken?: string;
}

interface Product extends Document {
  name: string;
  description: string;
  price: number;
  category: string;
  brand?: string;
  isDeleted: boolean;
}

interface Address extends Document {
  userId: string;
  street: string;
  city: string;
  country: string;
}

interface CartItem {
  productId: string;
  quantity: number;
}

interface Cart extends Document {
  userId: string;
  items: CartItem[];
}

interface Order extends Document {
  userId: string;
  items: CartItem[];
  address: string;
  status: 'pending' | 'paid' | 'shipped' | 'delivered';
  paymentMethod: string;
}

const UserSchema = new Schema({
  email: { type: String, unique: true },
  password: String,
  name: String,
  twoFactorSecret: String,
  twoFactorEnabled: { type: Boolean, default: false },
  role: { type: String, default: 'user' },
  refreshToken: String,
});

const ProductSchema = new Schema({
  name: String,
  description: String,
  price: Number,
  category: String,
  brand: String,
  isDeleted: { type: Boolean, default: false },
});

const AddressSchema = new Schema({
  userId: String,
  street: String,
  city: String,
  country: String,
});

const CartSchema = new Schema({
  userId: String,
  items: [{ productId: String, quantity: Number }],
});

const OrderSchema = new Schema({
  userId: String,
  items: [{ productId: String, quantity: Number }],
  address: String,
  status: { type: String, default: 'pending' },
  paymentMethod: String,
});

// ========== Services ==========

@Injectable()
class AuthService {
  constructor(
    @InjectModel('User') private userModel: Model<User>,
    private jwtService: JwtService,
  ) {}

  async register(dto: RegisterDto) {
    const existing = await this.userModel.findOne({ email: dto.email });
    if (existing) throw new BadRequestException('Email already exists');
    const hashed = await bcrypt.hash(dto.password, 10);
    const user = await this.userModel.create({ ...dto, password: hashed });
    return { id: user._id, email: user.email, name: user.name };
  }

  async login(dto: LoginDto) {
    const user = await this.userModel.findOne({ email: dto.email });
    if (!user || !(await bcrypt.compare(dto.password, user.password))) {
      throw new UnauthorizedException('Invalid credentials');
    }

    const payload = { email: user.email, sub: user._id, role: user.role };
    const accessToken = this.jwtService.sign(payload, { expiresIn: '15m' });
    const refreshToken = this.jwtService.sign(payload, {
      secret: getEnv('JWT_REFRESH_SECRET'),
      expiresIn: '7d',
    });

    await this.userModel.findByIdAndUpdate(user._id, { refreshToken });
    return { accessToken, refreshToken };
  }

  async refresh(refreshToken: string) {
    try {
      const payload = jwt.verify(refreshToken, getEnv('JWT_REFRESH_SECRET')) as any;
      const user = await this.userModel.findById(payload.sub);
      if (!user || user.refreshToken !== refreshToken) throw new UnauthorizedException();
      const newAccessToken = this.jwtService.sign(
        { email: user.email, sub: user._id, role: user.role },
        { expiresIn: '15m' }
      );
      return { accessToken: newAccessToken };
    } catch {
      throw new UnauthorizedException();
    }
  }

  async enable2FA(userId: string) {
    const secret = speakeasy.generateSecret({ name: 'EcomApp' });
    await this.userModel.findByIdAndUpdate(userId, {
      twoFactorSecret: secret.base32,
      twoFactorEnabled: true,
    });
    return { secret: secret.base32, otpauth_url: secret.otpauth_url };
  }

  async verify2FA(userId: string, token: string) {
    const user = await this.userModel.findById(userId);
    if (!user || !user.twoFactorEnabled) return false;
    return speakeasy.totp.verify({
      secret: user.twoFactorSecret,
      encoding: 'base32',
      token,
      window: 2,
    });
  }
}

@Injectable()
class ProductService {
  constructor(@InjectModel('Product') private productModel: Model<Product>) {}

  async search(query: string) {
    const regex = new RegExp(query, 'i');
    return this.productModel.find({
      isDeleted: false,
      $or: [
        { name: regex },
        { category: regex },
        { brand: regex },
      ],
    });
  }

  async findAll() {
    return this.productModel.find({ isDeleted: false });
  }

  async create(dto: ProductDto) {
    return this.productModel.create(dto);
  }

  async softDelete(id: string) {
    const product = await this.productModel.findByIdAndUpdate(id, { isDeleted: true }, { new: true });
    if (!product) throw new NotFoundException();
    return product;
  }
}

@Injectable()
class CartService {
  constructor(@InjectModel('Cart') private cartModel: Model<Cart>) {}

  async getCart(userId: string) {
    let cart = await this.cartModel.findOne({ userId });
    if (!cart) cart = await this.cartModel.create({ userId, items: [] });
    return cart;
  }

  async addItem(userId: string, dto: CartItemDto) {
    let cart = await this.getCart(userId);
    const itemIndex = cart.items.findIndex(i => i.productId === dto.productId);
    if (itemIndex > -1) {
      cart.items[itemIndex].quantity += dto.quantity;
    } else {
      cart.items.push(dto);
    }
    return cart.save();
  }

  async updateQuantity(userId: string, productId: string, quantity: number) {
    const cart = await this.getCart(userId);
    const item = cart.items.find(i => i.productId === productId);
    if (!item) throw new NotFoundException('Item not in cart');
    if (quantity <= 0) {
      cart.items = cart.items.filter(i => i.productId !== productId);
    } else {
      item.quantity = quantity;
    }
    return cart.save();
  }

  async deleteItem(userId: string, productId: string) {
    const cart = await this.getCart(userId);
    cart.items = cart.items.filter(i => i.productId !== productId);
    return cart.save();
  }
}

@Injectable()
class AddressService {
  constructor(@InjectModel('Address') private addressModel: Model<Address>) {}

  async create(userId: string, dto: AddressDto) {
    return this.addressModel.create({ ...dto, userId });
  }

  async update(id: string, userId: string, dto: AddressDto) {
    const addr = await this.addressModel.findOneAndUpdate(
      { _id: id, userId },
      dto,
      { new: true }
    );
    if (!addr) throw new NotFoundException();
    return addr;
  }

  async delete(id: string, userId: string) {
    const addr = await this.addressModel.findOneAndDelete({ _id: id, userId });
    if (!addr) throw new NotFoundException();
  }

  async findAll(userId: string) {
    return this.addressModel.find({ userId });
  }
}

// ========== Guards ==========

@Injectable()
class JwtAuthGuard {
  constructor(private jwtService: JwtService) {}

  async canActivate(req: any): Promise<boolean> {
    const auth = req.headers.authorization;
    if (!auth || !auth.startsWith('Bearer ')) return false;
    try {
      const token = auth.split(' ')[1];
      const payload = this.jwtService.verify(token);
      req.user = payload;
      return true;
    } catch {
      return false;
    }
  }
}

@Injectable()
class AdminGuard {
  async canActivate(req: any): Promise<boolean> {
    return req.user && req.user.role === 'admin';
  }
}

// ========== Controllers ==========

@ApiTags('Auth')
@Controller('auth')
class AuthController {
  constructor(private authService: AuthService) {}

  @Post('register')
  register(@Body() dto: RegisterDto) {
    return this.authService.register(dto);
  }

  @Post('login')
  login(@Body() dto: LoginDto) {
    return this.authService.login(dto);
  }

  @Post('refresh')
  refresh(@Body('refreshToken') refreshToken: string) {
    return this.authService.refresh(refreshToken);
  }

  @Post('2fa/enable')
  @UseGuards(JwtAuthGuard)
  enable2FA(@Request() req) {
    return this.authService.enable2FA(req.user.sub);
  }

  @Post('2fa/verify')
  @UseGuards(JwtAuthGuard)
  verify2FA(@Request() req, @Body() dto: TwoFADto) {
    const isValid = this.authService.verify2FA(req.user.sub, dto.token);
    if (!isValid) throw new UnauthorizedException('Invalid 2FA token');
    return { success: true };
  }
}

@ApiTags('Products')
@Controller('products')
export class ProductController {
  constructor(private productService: ProductService) {}

  @Get()
  findAll() {
    return this.productService.findAll();
  }

  @Get('search')
  search(@Query('q') q: string) {
    if (!q) return [];
    return this.productService.search(q);
  }
}

@ApiTags('Cart')
@Controller('cart')
@UseGuards(JwtAuthGuard)
@ApiBearerAuth()
export class CartController {
  constructor(private cartService: CartService) {}

  @Get()
  getCart(@Request() req) {
    return this.cartService.getCart(req.user.sub);
  }

  @Post()
  addItem(@Request() req, @Body() dto: CartItemDto) {
    return this.cartService.addItem(req.user.sub, dto);
  }

  @Put('item/:id/quantity')
  updateQuantity(@Request() req, @Param('id') productId: string, @Body() dto: UpdateCartItemQuantityDto) {
    return this.cartService.updateQuantity(req.user.sub, productId, dto.quantity);
  }

  @Delete('item/:id')
  deleteItem(@Request() req, @Param('id') productId: string) {
    return this.cartService.deleteItem(req.user.sub, productId);
  }
}

@ApiTags('Addresses')
@Controller('addresses')
@UseGuards(JwtAuthGuard)
@ApiBearerAuth()
export class AddressController {
  constructor(private addressService: AddressService) {}

  @Post()
  create(@Request() req, @Body() dto: AddressDto) {
    return this.addressService.create(req.user.sub, dto);
  }

  @Put(':id')
  update(@Request() req, @Param('id') id: string, @Body() dto: AddressDto) {
    return this.addressService.update(id, req.user.sub, dto);
  }

  @Delete(':id')
  delete(@Request() req, @Param('id') id: string) {
    return this.addressService.delete(id, req.user.sub);
  }

  @Get()
  findAll(@Request() req) {
    return this.addressService.findAll(req.user.sub);
  }
}

@ApiTags('Delivery & Payments')
@Controller()
@UseGuards(JwtAuthGuard)
@ApiBearerAuth()
export class MiscController {
  @Get('delivery-options')
  getDeliveryOptions() {
    return [
      { id: 'standard', name: 'Standart (3-5 kun)' },
      { id: 'express', name: 'Express (1-2 kun)' },
      { id: 'pickup', name: 'Olib ketish (do\'kondan)' },
    ];
  }

  @Post('payments/create')
  createPayment(@Body() dto: CreatePaymentDto) {
    return {
      success: true,
      paymentId: 'PAY-' + Date.now(),
      method: dto.method,
      status: 'paid',
    };
  }
}

@ApiTags('Admin Auth')
@Controller('admin/auth')
export class AdminAuthController {
  constructor(private authService: AuthService) {}

  @Post('login')
  async login(@Body() dto: AdminLoginDto) {
    const user = await this.authService.login(dto);
    const payload = jwt.verify(user.accessToken, getEnv('JWT_SECRET')) as any;
    if (payload.role !== 'admin') throw new UnauthorizedException('Admin only');
    return user;
  }
}

@ApiTags('Admin Products')
@Controller('admin/products')
@UseGuards(JwtAuthGuard, AdminGuard)
@ApiBearerAuth()
export class AdminProductController {
  constructor(private productService: ProductService) {}

  @Post()
  create(@Body() dto: ProductDto) {
    return this.productService.create(dto);
  }

  @Delete(':id')
  delete(@Param('id') id: string) {
    return this.productService.softDelete(id);
  }
}

// ========== AppModule ==========

@Module({
  imports: [
    ConfigModule.forRoot({ isGlobal: true }),
    MongooseModule.forRoot(getEnv('DB_URI')),
    MongooseModule.forFeature([
      { name: 'User', schema: UserSchema },
      { name: 'Product', schema: ProductSchema },
      { name: 'Address', schema: AddressSchema },
      { name: 'Cart', schema: CartSchema },
    ]),
    JwtModule.registerAsync({
      useFactory: () => ({
        secret: getEnv('JWT_SECRET'),
        signOptions: { expiresIn: '15m' },
      }),
    }),
  ],
  controllers: [
    AuthController,
    ProductController,
    CartController,
    AddressController,
    MiscController,
    AdminAuthController,
    AdminProductController,
  ],
  providers: [
    AuthService,
    ProductService,
    CartService,
    AddressService,
    JwtAuthGuard,
    AdminGuard,
    JwtService,
  ],
})
class AppModule {}

// ========== Bootstrap ==========

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  const config = new DocumentBuilder()
    .setTitle('E-commerce API')
    .setDescription('To‘liq foydalanuvchi + admin funksiyalari')
    .setVersion('1.0')
    .addBearerAuth()
    .build();

  const document = SwaggerModule.createDocument(app, config);
  SwaggerModule.setup('api', app, document);

  app.enableCors();
  const port = parseInt(process.env.PORT || '3000', 10);
  await app.listen(port);
  console.log(`🚀 Server is running on http://localhost:${port}`);
  console.log(`📚 Swagger: http://localhost:${port}/api`);
}

bootstrap();
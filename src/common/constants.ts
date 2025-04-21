import { config } from "process";

// Microservice names
export const USER_SERVICE = 'USER_SERVICE';
export const AUTH_SERVICE = 'AUTH_SERVICE';

// Microservice TCP hosts and ports
export const TCP_HOSTS = {
  USER_SERVICE: { host: 'localhost', port: 3002 },
  AUTH_SERVICE: { host: 'localhost', port: 3001 },
};

// External HTTP microservices
export const HTTP_SERVICES = {
  FLIGHT_SERVICE_BASE_URL: process.env.FLIGHT_SERVICE_URL,
  BOOKING_SERVICE_BASE_URL: process.env.BOOKING_SERVICE_URL,
};

// Patterns
export const PATTERNS = {
  LOGIN: 'login',
  REGISTER: 'register',
  GET_USER_BY_ID: 'get_user_by_id',
};

import type { AppProps } from 'next/app';
import 'next/config';
export default function App({ Component, pageProps }: AppProps) {
  return <Component {...pageProps} />;
}

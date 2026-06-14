
FROM ruby:3.3-alpine


RUN apk add --no-cache build-base sqlite-dev

ARG BUILD_DIGEST=unknown
RUN echo "$BUILD_DIGEST" > /etc/formto-digest

WORKDIR /app


COPY Gemfile Gemfile.lock ./


RUN bundle config set --local without 'development test' && \
    bundle install --jobs 4 --retry 3


COPY . .


EXPOSE ${PORT:-3000}

ARG APP_VERSION=v1.1
ENV APP_VERSION=$APP_VERSION

CMD ["bundle", "exec", "puma", "-C", "config/puma.rb", "config.ru"]

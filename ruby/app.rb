require 'sinatra/base'
require 'mysql2'
require 'mysql2-cs-bind'
require 'erubis'
require 'redis'

module Ishocon1
  class AuthenticationError < StandardError; end
  class PermissionDenied < StandardError; end
end

class Ishocon1::WebApp < Sinatra::Base
  session_secret = ENV['ISHOCON1_SESSION_SECRET'] || 'showwin_happy' * 10
  use Rack::Session::Cookie, key: 'rack.session', secret: session_secret
  set :erb, escape_html: true
  set :public_folder, File.expand_path('../public', __FILE__)
  set :protection, true

  @@redis = Redis.new(url: ENV['REDIS_URL'] || 'redis://localhost:6379/0')

  helpers do
    def config
      @config ||= {
        db: {
          host: ENV['ISHOCON1_DB_HOST'] || 'localhost',
          port: ENV['ISHOCON1_DB_PORT'] && ENV['ISHOCON1_DB_PORT'].to_i,
          username: ENV['ISHOCON1_DB_USER'] || 'ishocon',
          password: ENV['ISHOCON1_DB_PASSWORD'] || 'ishocon',
          database: ENV['ISHOCON1_DB_NAME'] || 'ishocon1'
        }
      }
    end

    def db
      return Thread.current[:ishocon1_db] if Thread.current[:ishocon1_db]
      client = Mysql2::Client.new(
        host: config[:db][:host],
        port: config[:db][:port],
        username: config[:db][:username],
        password: config[:db][:password],
        database: config[:db][:database],
        reconnect: true
      )
      client.query_options.merge!(symbolize_keys: true)
      Thread.current[:ishocon1_db] = client
      client
    end

    def setup_cache
      @@redis.flushdb

      $product_comments = {}
      $products = {}

      product_comments_query = <<SQL
SELECT product_id, users.name as user_name, content, created_at
FROM comments
INNER JOIN users on comments.user_id = users.id
SQL
      products_query = <<SQL
SELECT *
FROM products
SQL
      db.xquery(product_comments_query).each do |comment|
        comment = {
          product_id: comment[:product_id],
          user_name: comment[:user_name],
          content: comment[:content],
          created_at: comment[:created_at],
        }
        add_product_comment(comment)
      end
      db.xquery(products_query).each do |product|
        add_product_comment(product)
      end
    end

    def add_product(product)
      $products[product[:id]] = product
    end

    def add_product_comment(comment)
      if $product_comments.has_key?(comment[:product_id])
        $product_comments.fetch(comment[:product_id]) << comment
        # Re-sort after insertion
        $product_comments[comment[:product_id]].sort_by! { |c| c[:created_at] }.reverse!
      else
        $product_comments[comment[:product_id]] = [comment]
      end
    end

    def time_now_db
      Time.now - 9 * 60 * 60
    end

    def authenticate(email, password)
      user = db.xquery('SELECT * FROM users WHERE email = ?', email).first
      fail Ishocon1::AuthenticationError unless user && user[:password] == password
      session[:user_id] = user[:id]
    end

    def authenticated!
      fail Ishocon1::PermissionDenied unless current_user
    end

    def current_user
      db.xquery('SELECT * FROM users WHERE id = ?', session[:user_id]).first
    end

    def update_last_login(user_id)
      db.xquery('UPDATE users SET last_login = ? WHERE id = ?', time_now_db, user_id)
    end

    def buy_product(product_id, user_id)
      db.xquery('INSERT INTO histories (product_id, user_id, created_at) VALUES (?, ?, ?)',
        product_id, user_id, time_now_db)
    
      # Update Redis cache
      @@redis.sadd("user:#{user_id}:purchases", product_id.to_s)
      @@redis.del("user:#{user_id}:total_pay")
    end
    
    def initialize_user_purchases(user_id)
      key = "user:#{user_id}:purchases"
    
      # Fetch purchase history from the database
      purchases = db.xquery('SELECT product_id FROM histories WHERE user_id = ?', user_id).map { |row| row[:product_id] }
      @@redis.sadd(key, purchases.map(&:to_s)) unless purchases.empty?
    end

    def already_bought?(product_id)
      return false unless current_user
      key = "user:#{current_user[:id]}:purchases"
    
      initialize_user_purchases(current_user[:id]) unless @@redis.exists(key) # Existence check here
      @@redis.sismember(key, product_id.to_s)
    end

    def create_comment(product_id, user, content)
      add_product_comment({product_id:, user_name: user[:name], content:, created_at: time_now_db})
    end
  end

  error Ishocon1::AuthenticationError do
    session[:user_id] = nil
    halt 401, erb(:login, layout: false, locals: { message: 'ログインに失敗しました' })
  end

  error Ishocon1::PermissionDenied do
    halt 403, erb(:login, layout: false, locals: { message: '先にログインをしてください' })
  end

  get '/login' do
    session.clear
    erb :login, layout: false, locals: { message: 'ECサイトで爆買いしよう！！！！' }
  end

  post '/login' do
    authenticate(params['email'], params['password'])
    update_last_login(current_user[:id])
    redirect '/'
  end

  get '/logout' do
    session[:user_id] = nil
    session.clear
    redirect '/login'
  end

  get '/' do
    page = (params[:page] || '0').to_i
    start = 10000 - ((page + 1) * 50) + 1
    last = 10000 - (page * 50)
    product_query = <<SQL
select id, name, LEFT(description, 70) as description, image_path, price, created_at
from products
where id >= #{start} and id <= #{last}
order by ID desc
SQL
    products = db.xquery(product_query)
    erb :index, locals: { products:, comments_by_product: $product_comments }
  end

  get '/users/:user_id' do
    page = @@redis.get("user_page:#{params[:user_id]}")
    unless page
      user = db.xquery('select * from users where id = ?', params[:user_id]).first
      products_query = <<SQL
select products.id, products.name, LEFT(products.description, 70) as description, products.image_path, products.price, histories.created_at
from histories
left outer join products
on histories.product_id = products.id
where histories.user_id = ?
order by histories.id desc
limit 30
SQL
      products = db.xquery(products_query, params[:user_id]).to_a
      total_pay = @@redis.get("user:#{params[:user_id]}:total_pay")
      unless total_pay
        total_pay_query = <<SQL
select SUM(p.price) as total_pay
from histories
left outer join products
on histories.product_id = products.id
where histories.user_id = ?
SQL
        total_pay = db.xquery(total_pay_query).first[:total_pay]
        @@redis.set("user:#{user[:id]}:total_pay", total_pay)
      end

      page = { products: products, user: user, total_pay: total_pay }
      @@redis.set("user_page:#{params[:user_id]}", Marshal.dump(page))
    else
      page = Marshal.load(cache)
    end
    erb :mypage, locals: page
  end

  get '/products/:product_id' do
    # product = db.xquery('SELECT * FROM products WHERE id = ?', params[:product_id]).first
    product = $products[:product_id]
    key = "product:comments:#{product[:id]}"

    if @@redis.exists(key)
      # Get it from Redis
      comments = @@redis.get(key)
      comments = comments ? Marshal.load(comments) : []
    else
      # Use the current data from comments
      comments = $product_comments[product[:id]] || []

      # Cashing in Redis
      @@redis.set(key, Marshal.dump(comments))
    end

    erb :product, locals: { product: product, comments: comments }
  end

  post '/products/buy/:product_id' do
    authenticated!
    buy_product(params[:product_id], current_user[:id])
    redirect "/users/#{current_user[:id]}"
  end

  post '/comments/:product_id' do
    authenticated!
    create_comment(params[:product_id].to_i, current_user, params[:content])
    redirect "/users/#{current_user[:id]}"
  end

  get '/initialize' do
    db.query('DELETE FROM users WHERE id > 5000')
    db.query('DELETE FROM products WHERE id > 10000')
    db.query('DELETE FROM comments WHERE id > 200000')
    db.query('DELETE FROM histories WHERE id > 500000')

    setup_cache
    "Finish"
  end
end

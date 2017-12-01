# coding=utf-8
import os
from flask import Flask, render_template, session, redirect, \
    url_for, flash, current_app, request
from flask_script import Manager, Shell
from flask_migrate import Migrate, MigrateCommand
from flask_bootstrap import Bootstrap
from flask_login import UserMixin, LoginManager, login_required, \
    login_user, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, SelectField, \
    BooleanField, IntegerField, ValidationError
from wtforms.validators import Required, EqualTo, Length, Regexp
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

import random
import json
import time
import MySQLdb as mysql

import mythread
import udp_conn

db2 = mysql.connect(user='root', passwd='', db='test03', charset='utf8')
db2.autocommit(True)
c = db2.cursor()

'''
Config
'''
basedir = os.path.abspath(os.path.dirname(__file__))


def make_shell_context():
    return dict(app=app, db=db, User=User, Role=Role)


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://root:@localhost/test03?charset=utf8'
app.config['SQLALCHEMY_COMMIT_ON_TEARDOWN'] = True
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['AdminPassword'] = '000000'
app.config['SECRET_KEY'] = "this is a secret_key"
app.config['BOOTSTRAP_SERVE_LOCAL'] = True
app.config['DEBUG'] = 'True'
db = SQLAlchemy(app)
manager = Manager(app)
bootstrap = Bootstrap(app)
migrate = Migrate(app, db)
manager.add_command('db', MigrateCommand)
manager.add_command('shell', Shell(make_shell_context))
login_manager = LoginManager(app)

login_manager.session_protection = 'strong'
login_manager.login_view = 'login'
login_manager.login_message = u"你需要登录才能访问这个页面."

# 采样频率
SAMPLE_ARG = 10000  # 默认采样长度，开始满长渡
# BOOL_DATA_FULL = [False, False, False, False]  # 判断每个轮对数据是否达到SAMPLE_ARG长度
# BOOL_INSERT = False  # 标记是否插入数据
SPEED_ARG = 1000 # 默认速度
LAST_PACK = [-1, -1, -1, -1]  # 每个轮对每次查询的最后包号

'''
Models
'''


class Role(db.Model):
    __tablename__ = 'roles'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), unique=True)
    users = db.relationship('User', backref='role', lazy='dynamic')

    @staticmethod
    def insert_roles():
        roles = ('Normal', 'Admin')
        for r in roles:
            role = Role.query.filter_by(name=r).first()
            if role is None:
                role = Role(name=r)
            db.session.add(role)
        db.session.commit()

    def __repr__(self):
        return '<Role %r>' % self.name


class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, index=True)
    # password = db.Column(db.String(128), default=123456)
    password_hash = db.Column(db.String(128))
    role_id = db.Column(db.Integer, db.ForeignKey('roles.id'))

    def __init__(self, **kwargs):
        super(User, self).__init__(**kwargs)
        # 新添加的用户，初始其角色为普通用户。
        if self.role is None:
            self.role = Role.query.filter_by(name='Normal').first()

    def __repr__(self):
        return '<User %r>' % self.username

    # 初次运行程序时生成初始管理员的静态方法
    @staticmethod
    def generate_admin():
        admin = Role.query.filter_by(name='Admin').first()
        u = User.query.filter_by(role=admin).first()
        if u is None:
            u = User(username='admin', \
                     password=current_app.config['AdminPassword'], \
                     role=Role.query.filter_by(name='Admin').first())
            db.session.add(u)
        db.session.commit()

    @property
    def password(self):
        # raise AttributeError('password is not a readable attribute')
        pass

    @password.setter
    def password(self, password):
        if password == '':
            password = '123456'
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)


class InstWheel(db.Model):
    __tablename__ = 'InstWheel'
    id = db.Column(db.Integer, primary_key=True)
    deviceid = db.Column(db.Integer, nullable=False)
    package = db.Column(db.Integer)
    data1 = db.Column(db.Float)
    data2 = db.Column(db.Float)
    data3 = db.Column(db.Float)
    data4 = db.Column(db.Float)


class CharaValue(db.Model):
    __tablename__ = 'CharaValue'
    id = db.Column(db.Integer, primary_key=True)
    DeviceID = db.Column(db.Integer, nullable=False)
    data1_maxValue = db.Column(db.Float)
    data1_meanValue = db.Column(db.Float)
    data2_maxValue = db.Column(db.Float)
    data2_meanValue = db.Column(db.Float)
    data3_maxValue = db.Column(db.Float)
    data3_meanValue = db.Column(db.Float)
    data4_maxValue = db.Column(db.Float)
    data4_meanValue = db.Column(db.Float)


'''
Forms
'''


class LoginForm(FlaskForm):
    username = StringField(u'用户名', validators=[Required()])
    password = PasswordField(u'密码', validators=[Required()])
    remember_me = BooleanField(u'记住我')
    submit = SubmitField(u'登录')


class SearchForm(FlaskForm):
    username = StringField(u'用户名', validators=[Required()])
    submit = SubmitField(u'搜索')


class UserForm(FlaskForm):
    username = StringField(u'用户名', validators=[Required()])
    password = PasswordField(u'密码', default='123456', description=u'默认密码为123456')
    role = SelectField(u'身份', coerce=int)

    submit = SubmitField(u'添加')

    def __init__(self, *args, **kargs):
        super(UserForm, self).__init__(*args, **kargs)
        self.role.choices = [(role.id, role.name)
                             for role in Role.query.order_by(Role.name).all()]

    def validate_username(self, field):
        if User.query.filter_by(username=field.data).first():
            raise ValidationError(u'此用户已存在，请检查！')


class EditForm(FlaskForm):
    username = StringField(u'用户名', validators=[Required()])
    # password = PasswordField(u'密码', validators=[Required(), Length(1, 64), \
    #                                             Regexp('^[a-zA-Z0-9_.]*$', 0, \
    #                                                    u'密码由字母、数字和_.组成')])
    role = SelectField(u'身份', coerce=int)
    submit = SubmitField(u'修改')

    def __init__(self, user, *args, **kargs):
        super(EditForm, self).__init__(*args, **kargs)
        self.role.choices = [(role.id, role.name)
                             for role in Role.query.order_by(Role.name).all()]
        self.user = user


class ChangePasswordForm(FlaskForm):
    old_password = PasswordField(u'旧密码', validators=[Required(message=u'密码不能为空')])
    password = PasswordField(u'新密码', validators=[
        Required(message=u'密码不能为空'), EqualTo('password2', message=u'密码必须匹配。')])
    password2 = PasswordField(u'确认新密码', validators=[Required(message=u'密码不能为空')])
    submit = SubmitField(u'更改')


'''
views
'''


@app.route('/', methods=['GET'])
def index():
    return render_template('index.html')


# 增加新用户
@app.route('/add-user', methods=['GET', 'POST'])
@login_required
def add_user():
    form = UserForm()
    if form.validate_on_submit():
        user = User(username=form.username.data, password=form.password.data)
        user.role = Role.query.get(form.role.data)
        db.session.add(user)
        flash(u'成功添加用户')
        return redirect(url_for('go_user'))
    return render_template('add_user.html', form=form)


# 删除用户
@app.route('/remove-user/<int:id>', methods=['GET', 'POST'])
@login_required
def remove_user(id):
    user = User.query.get_or_404(id)
    if user.username == 'admin' and user.role == Role.query.filter_by(name='Admin').first():
        flash(u'不能删除admin管理员')
    else:
        db.session.delete(user)
        flash(u'成功删除此用户')
    return redirect(url_for('go_user'))


# 修改用户资料
@app.route('/edit-user/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_user(id):
    user = User.query.get_or_404(id)
    form = EditForm(user=user)
    if form.validate_on_submit():
        user.username = form.username.data
        # user.password = form.password.data
        user.role = Role.query.get(form.role.data)
        db.session.add(user)
        flash(u'个人信息已更改')
        return redirect(url_for('go_user'))
    form.username.data = user.username
    # form.password.data = user.password
    form.role.data = user.role_id
    return render_template('edit_user.html', form=form, user=user)


# 更改密码
@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    form = ChangePasswordForm()
    if form.validate_on_submit():
        if current_user.verify_password(form.old_password.data):
            current_user.password = form.password.data
            db.session.add(current_user)
            flash(u'你的密码已经更新。', 'success')
            return redirect(url_for('index'))
        else:
            flash(u'密码无效。', 'warning')
    return render_template("change_password.html", form=form)


# 登录功能
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user is not None and user.verify_password(form.password.data):
            login_user(user, form.remember_me.data)
            is_admin = (user.role == Role.query.filter_by(name='Admin').first())
            session['is_admin'] = is_admin
            return render_template('index.html', current_user=user)
        flash(u'用户名或密码错误！')
    return render_template('login.html', form=form)


# 登出
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash(u'成功注销！')
    return redirect(url_for('login'))


# 用户管理
@app.route('/user/go_user/', methods=['GET', 'POST'])
@login_required
def go_user():
    form = SearchForm()
    admin = Role.query.filter_by(name='Admin').first()
    if form.validate_on_submit():
        # 获得用户列表，用form中的字符串模糊查询
        users = User.query.filter(User.username.like('%{}%'.format(form.username.data))).all()
        print users
    else:
        users = User.query.order_by(User.role_id.desc(), User.username.asc()).all()
    return render_template('user.html', form=form, users=users, admin=admin)


'''
轮对数据
'''


@app.route('/data/go_data/', methods=['GET'])
@login_required
def go_data():
    global SPEED_ARG
    global SAMPLE_ARG
    return render_template("data.html", sample_num=SAMPLE_ARG, speed_num=SPEED_ARG)


# 模拟数据，test
PACKAGE = 1
@app.route('/data/insert_data/', methods=['GET'])
def insert_data():
    try:
        global PACKAGE
        data1 = 60 + random.random() * 10
        data2 = 60 + random.random() * 10
        data3 = 60 + random.random() * 10
        data4 = 60 + random.random() * 10
        ret = c.executemany(
            "insert into `InstWheel` (`deviceid`, `package`,`data1`,`data2`,`data3`,`data4`) values(%s,%s,%s,%s,%s,%s)",
            [(1, PACKAGE, data1, data2, data3, data4), (1, PACKAGE + 1, data1, data2, data3, data4)])

        ret = c.executemany(
            "insert into `InstWheel` (`deviceid`, `package`,`data1`,`data2`,`data3`,`data4`) values(%s,%s,%s,%s,%s,%s)",
            [(2, PACKAGE, data1, data2, data3, data4), (2, PACKAGE + 1, data1, data2, data3, data4)])

        ret = c.executemany(
            "insert into `InstWheel` (`deviceid`, `package`,`data1`,`data2`,`data3`,`data4`) values(%s,%s,%s,%s,%s,%s)",
            [(3, PACKAGE, data1, data2, data3, data4), (3, PACKAGE + 1, data1, data2, data3, data4)])

        ret = c.executemany(
            "insert into `InstWheel` (`deviceid`, `package`,`data1`,`data2`,`data3`,`data4`) values(%s,%s,%s,%s,%s,%s)",
            [(4, PACKAGE, data1, data2, data3, data4), (4, PACKAGE + 1, data1, data2, data3, data4)])

        PACKAGE = PACKAGE + 2
    except mysql.Error:
        pass
    return 'OK'


# 查询数据
def query_data(deviceid, num, last_package):
    global SAMPLE_ARG
    sql = ""
    # 开始查询
    if last_package is None:  # 判断是否移动
        sql = "select package, data1, data2, data3,data4 from InstWheel where deviceid=%d order by id desc limit %d" % \
              (deviceid, num)
    # 增量查询
    else:
        # sql = "select package, data1, data2,data3, data4 from InstWheel where deviceid=%d and package >%d order by id desc limit %d " % \
        #       (deviceid, last_package, num)
        sql = "select package, data1, data2,data3, data4 from InstWheel where deviceid=%d and package >%d order by id limit %d " % \
              (deviceid, last_package, num)
    c.execute(sql)
    fetch_data = c.fetchall()
    results = []
    if last_package is None:
        ii = range(0, fetch_data.__len__())[::-1]
    else:
        ii = range(0, fetch_data.__len__())

    for i in ii:
        results.append({'package': fetch_data[i][0], 'data1': fetch_data[i][1], 'data2': fetch_data[i][2],
                        'data3': fetch_data[i][3], 'data4': fetch_data[i][4]})
    return results


# 查询轮对数据 波形
@app.route('/data/get_data/', methods=['GET'])
@login_required
def get_data():
    global LAST_PACK
    device_id = int(request.args.get('device_id'))
    sample_arg = int(request.args.get('sample_num'))  # 包号区间
    speed_arg = int(request.args.get('speed_num'))  # 查询速度

    # 开始查询
    if speed_arg == 0:
        results = [{'package': 0}] * sample_arg
        data = query_data(device_id, sample_arg, None)
        data_len = len(data)
        for i, j in zip(range(sample_arg - data_len, sample_arg), range(0, data_len)):
            results[i] = data[j]
        if data_len != 0:
            LAST_PACK[device_id - 1] = results[sample_arg - 1]['package']
    # 增量查询
    else:
        results = query_data(device_id, speed_arg, LAST_PACK[device_id - 1])
        if results.__len__() != 0:
            LAST_PACK[device_id - 1] = results[results.__len__() - 1]['package']
    return "%s" % json.dumps(results)


# 查询轮对数据 实时状态（从InstWheel表）
@app.route('/data/get_currentData')
def get_dataStatus():
    sql = "select * from \
(select deviceid,data1,data2,data3,data4 from InstWheel where deviceid=1 order by id desc limit 1) t1 \
union \
select * from \
(select deviceid,data1,data2,data3,data4 from InstWheel where deviceid=2 order by id desc limit 1) t2 \
union \
select * from \
(select deviceid,data1,data2,data3,data4 from InstWheel where deviceid=3 order by id desc limit 1) t3 \
union \
select * from \
(select deviceid,data1,data2,data3,data4 from InstWheel where deviceid=4 order by id desc limit 1) t4"
    c.execute(sql)
    fetch_data = c.fetchall()
    results = []
    for i in range(0, fetch_data.__len__()):
        results.append({'device_id': fetch_data[i][0], 'data1': fetch_data[i][1], 'data2': fetch_data[i][2],
                        'data3': fetch_data[i][3], 'data4': fetch_data[i][4]})
    return "%s" % json.dumps(results)


# 查询轮对数据 均值（从CharaValue表）
@app.route('/data/get_meanCharaValue')
def get_meanCharaValue():
    # device_id = int(request.args.get('device_id'))
    sql = "select DeviceID,data1_meanValue,data2_meanValue,data3_meanValue,data4_meanValue from CharaValue "
    c.execute(sql)
    fetch_data = c.fetchall()
    results = []
    for i in range(0, fetch_data.__len__()):
        results.append({'device_id': fetch_data[i][0], 'data1_meanValue': fetch_data[i][1], \
                        'data2_meanValue': fetch_data[i][2], 'data3_meanValue': fetch_data[i][3],
                        'data4_meanValue': fetch_data[i][4]})
    if len(results) == 0:
        return "none"
    return "%s" % json.dumps(results)


# 报表处理
@app.route('/data/go_report/')
@login_required
def go_report():
    sql = "select DeviceID,data1_maxValue, data1_meanValue, data2_maxValue, data2_meanValue, data3_maxValue, data3_meanValue, data4_maxValue, data4_meanValue from CharaValue "
    c.execute(sql)
    fetch_data = c.fetchall()
    objs = []
    for i in range(0, fetch_data.__len__()):
        objs.append(
            {'device_id': fetch_data[i][0], 'data1_maxValue': fetch_data[i][1], 'data1_meanValue': fetch_data[i][2],
             'data2_maxValue': fetch_data[i][3], 'data2_meanValue': fetch_data[i][4],
             'data3_maxValue': fetch_data[i][5], 'data3_meanValue': fetch_data[i][6],
             'data4_maxValue': fetch_data[i][7], 'data4_meanValue': fetch_data[i][8]})
    return render_template('report.html', objs=objs)


# UDP 控制
@app.route('/data/start_data/', methods=['GET'])
def start_data():
    # 創建線程通訊
    t = mythread.MyThread(func=udp_conn.udp_start)
    t.start()
    t.join()
    udp_res = t.get_result()
    if udp_res == 'OK':
        return 'ok'
    else:
        return 'error'


@app.route('/data/stop_data/', methods=['GET'])
def stop_data():
    # 創建線程通訊
    t = mythread.MyThread(func=udp_conn.udp_stop)
    t.start()
    t.join()
    udp_res = t.get_result()
    if udp_res == 'OK':
        sql = "delete from InstWheel"
        c.execute(sql)
        return 'ok'
    else:
        return 'error'


@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404


@app.errorhandler(500)
def internal_server_error(e):
    return render_template('500.html'), 500


# 加载用户的回调函数
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


'''
增加命令'python app.py init' 
以增加身份与初始管理员帐号
'''


@manager.command
def init():
    from app import Role, User
    Role.insert_roles()
    User.generate_admin()


if __name__ == '__main__':
    # manager.run()
    app.run()

import Sequelize from "sequelize";
import { sequelize } from "../config/database";
import { User } from "./user";





export const UserRefreshToken = sequelize.define('user_refresh_tokens', {

  id: {
    type: Sequelize.INTEGER(10),
    allowNull: false,
    primaryKey: true,
    autoIncrement: true
  },

  user_id: {
    type: Sequelize.INTEGER(10),
    allowNull: false,
    references: {
      model: User,
      key: 'id'
    }
  },
  token: {
    type: Sequelize.STRING(255),
    allowNull: false
  },
  expires: {
    type: Sequelize.DATE,
    allowNull: false
  },
  createdByIp: {
    type: Sequelize.STRING(255),
    allowNull: true
  },
  revoked: {
    type: Sequelize.DATE,
    allowNull: true
  },
  revokedByIp: {
    type: Sequelize.STRING(255),
    allowNull: true
  },
  replacedByToken: {
    type: Sequelize.STRING(255),
    allowNull: true
  },
  createdAt: {
    type: Sequelize.DATE,
    allowNull: true

  },
  updatedAt: {
    type: Sequelize.DATE,
    allowNull: true
  },
},
  {
    freezeTableName: true,
    tableName: 'user_refresh_tokens'
  })


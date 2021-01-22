

import Sequelize from "sequelize";
import { sequelize } from "../config/database";
import { User } from "./user";

export const Transaction = sequelize.define('transactions', {

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
  amount: {
    allowNull: false,
    type: Sequelize.STRING,
  },

  remarks: {
    allowNull: true,
    type: Sequelize.STRING,
  },

  status: {
    allowNull: true,
    type: Sequelize.STRING,
  },
  gateway: {
    allowNull: true,
    type: Sequelize.STRING,
  },
  payment_gateway_response: {
    allowNull: true,
    type: Sequelize.JSON,
  },
  payment_gateway_trx_id: {
    allowNull: true,
    type: Sequelize.STRING,
  },

  payment_gateway_callback_response: {
    allowNull: true,
    type: Sequelize.JSON,
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
    tableName: 'transactions'
  })


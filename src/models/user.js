

import Sequelize from "sequelize";
import { sequelize } from "../config/database";

export const User = sequelize.define('users', {

    id: {
        type: Sequelize.INTEGER(10),
        allowNull: false,
        primaryKey: true,
        autoIncrement: true
    },

    first_name: {
        type: Sequelize.STRING(255),
        allowNull: false
    },

    last_name: {
        type: Sequelize.STRING(255),
        allowNull: true
    },

    email: {
        type: Sequelize.STRING(255),
        allowNull: true
    },
    phone_no: {
        type: Sequelize.STRING(255),
        allowNull: true
    },
    password: {
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
        tableName: 'users'
    })


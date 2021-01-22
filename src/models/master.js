import Sequelize from "sequelize";
import { sequelize } from "../config/database";

export const Master = sequelize.define('master', {
    id: {
        allowNull: false,
        autoIncrement: true,
        primaryKey: true,
        type: Sequelize.INTEGER
    },
    client_id: {
        type: Sequelize.STRING
    },
    secret_key: {
        allowNull: true,
        type: Sequelize.STRING
    },
},
    {
        freezeTableName: true,
        tableName: 'master',
        timestamps:false
    })
